package truenas

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

type Client struct {
	endpoint string
	apiKey   string
	// username is required by auth.login_ex. When empty the client falls back to
	// the deprecated auth.login_with_api_key.
	username string
	// debug gates verbose wire logging. Even when true, logged frames are passed
	// through redactForLog so credentials never reach a log file.
	debug     bool
	tlsConfig *tls.Config

	// connMu protects conn and authenticated; also gates connect/authenticate
	connMu        sync.Mutex
	conn          *websocket.Conn
	authenticated bool

	// writeMu protects concurrent WebSocket writes
	writeMu sync.Mutex

	// pending maps request ID -> response channel for concurrent request multiplexing
	pendingMu sync.Mutex
	pending   map[string]chan *responseResult

	requestID atomic.Uint64
}

type responseResult struct {
	resp *APIResponse
	err  error
}

type ConnectRequest struct {
	Msg     string   `json:"msg"`
	Version string   `json:"version"`
	Support []string `json:"support"`
}

type ConnectResponse struct {
	Msg     string `json:"msg"`
	Session string `json:"session"`
}

type APIRequest struct {
	ID     string        `json:"id"`
	Msg    string        `json:"msg"`
	Method string        `json:"method"`
	Params []interface{} `json:"params,omitempty"`
}

type APIResponse struct {
	ID     string          `json:"id"`
	Msg    string          `json:"msg"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *APIError       `json:"error,omitempty"`
}

type APIError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Trace   interface{} `json:"trace,omitempty"` // Can be string or object
}

func NewClient(endpoint, apiKey string, tlsConfig *tls.Config) (*Client, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("endpoint cannot be empty")
	}
	if apiKey == "" {
		return nil, fmt.Errorf("apiKey cannot be empty")
	}
	return &Client{
		endpoint:  endpoint,
		apiKey:    apiKey,
		tlsConfig: tlsConfig,
		pending:   make(map[string]chan *responseResult),
	}, nil
}

// SetUsername sets the username that owns the API key. It is required by
// auth.login_ex; without it the client uses the deprecated login call.
func (c *Client) SetUsername(u string) { c.username = u }

// SetDebug enables verbose wire logging. Logged frames are still redacted, so
// credentials are never written even in debug mode.
func (c *Client) SetDebug(d bool) { c.debug = d }

// connect establishes the WebSocket connection and starts the read loop.
// Must be called with connMu held.
func (c *Client) connect() error {
	if c.conn != nil {
		return nil
	}

	urls, err := c.buildConnectionURLs()
	if err != nil {
		return err
	}

	wsDialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
		TLSClientConfig:  c.tlsConfig, // Always use TLS config (only wss:// allowed)
		ReadBufferSize:   65536,       // 64KB read buffer to handle large messages
		WriteBufferSize:  65536,       // 64KB write buffer to handle large messages
	}

	var lastErr error
	for _, url := range urls {
		log.Printf("Connecting to %s...", url)
		conn, _, err := wsDialer.Dial(url, nil)
		if err != nil {
			log.Printf("Connection failed: %v", err)
			lastErr = err
			continue
		}

		// Set read limit to handle large responses (e.g., large upgrade summaries)
		conn.SetReadLimit(10 * 1024 * 1024) // 10MB

		// Send connect message as per TrueNAS WebSocket protocol
		connectMsg := ConnectRequest{
			Msg:     "connect",
			Version: "1",
			Support: []string{"1"},
		}
		if c.debug {
			log.Printf("Sending connect message: %+v", connectMsg)
		}
		if err := conn.WriteJSON(connectMsg); err != nil {
			conn.Close()
			lastErr = fmt.Errorf("failed to send connect message: %w", err)
			continue
		}

		// Read connect response directly (before read loop starts)
		var connectResp ConnectResponse
		if err := conn.ReadJSON(&connectResp); err != nil {
			conn.Close()
			lastErr = fmt.Errorf("failed to read connect response: %w", err)
			continue
		}
		if c.debug {
			log.Printf("Received connect response: %+v", connectResp)
		}

		if connectResp.Msg != "connected" {
			conn.Close()
			lastErr = fmt.Errorf("unexpected connect response: %s", connectResp.Msg)
			continue
		}

		c.conn = conn
		c.authenticated = false

		// Start the read loop to multiplex concurrent responses
		go c.readLoop(conn)

		log.Printf("Successfully connected via %s", url)
		return nil
	}

	return fmt.Errorf("all connection attempts failed: %w", lastErr)
}

// readLoop reads all WebSocket responses and routes them to the waiting callers
// via the pending map. Runs as a goroutine for the lifetime of the connection.
func (c *Client) readLoop(conn *websocket.Conn) {
	for {
		var resp APIResponse
		if err := conn.ReadJSON(&resp); err != nil {
			// Connection dropped - fail all pending requests
			c.failAllPending(fmt.Errorf("failed to read response: %w", err))

			// Reset connection state if it's still this connection
			c.connMu.Lock()
			if c.conn == conn {
				c.conn = nil
				c.authenticated = false
			}
			c.connMu.Unlock()
			return
		}

		if c.debug {
			// Auth responses can carry a session token; redact before logging.
			respJSON, _ := json.Marshal(resp)
			log.Printf("Received response: %s", redactForLog(string(respJSON)))
			log.Printf("Result length: %d bytes", len(resp.Result))
		}

		// Route response to the waiting caller
		c.pendingMu.Lock()
		ch, ok := c.pending[resp.ID]
		if ok {
			delete(c.pending, resp.ID)
		}
		c.pendingMu.Unlock()

		if ok {
			ch <- &responseResult{resp: &resp}
		} else if resp.ID != "" {
			log.Printf("Warning: received response for unknown request ID %s (may have timed out)", resp.ID)
		}
	}
}

// failAllPending delivers an error to all in-flight requests (called on disconnect)
func (c *Client) failAllPending(err error) {
	c.pendingMu.Lock()
	pending := c.pending
	c.pending = make(map[string]chan *responseResult)
	c.pendingMu.Unlock()

	for _, ch := range pending {
		ch <- &responseResult{err: err}
	}
}

// buildConnectionURLs returns URLs to try in order
func (c *Client) buildConnectionURLs() ([]string, error) {
	// SECURITY: Reject ws:// URLs entirely - TrueNAS will revoke API keys used over unencrypted connections
	if strings.HasPrefix(c.endpoint, "ws://") {
		return nil, fmt.Errorf("SECURITY ERROR: ws:// (unencrypted) connections are not allowed. TrueNAS will revoke API keys used over ws://. Use wss:// instead")
	}

	// If full wss:// URL provided, use it
	if strings.HasPrefix(c.endpoint, "wss://") {
		return []string{c.endpoint}, nil
	}

	// Bare "host" or "host:port". Upstream discarded any port given here and forced
	// 443, which breaks every install whose web UI has been moved off the default --
	// TrueNAS exposes that as ui_httpsport, and a reverse proxy running on the NAS
	// commonly takes 443 for itself. Honour an explicit port; default to 443 only
	// when none was supplied. net.SplitHostPort handles bracketed IPv6 correctly and
	// returns an error for a bare host, which is exactly the fallback we want.
	host, port := c.endpoint, "443"
	if h, p, err := net.SplitHostPort(c.endpoint); err == nil {
		host, port = h, p
	} else {
		// No port. If the host is a bracketed IPv6 literal ("[fd00::1]"), strip the
		// brackets: JoinHostPort re-adds them, and without this we'd emit the
		// double-bracketed "wss://[[fd00::1]]:443/websocket".
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = host[1 : len(host)-1]
		}
	}
	// NOTE ON THE ENDPOINT: this client speaks the legacy DDP-style protocol
	// ({"msg":"connect"}, {"msg":"method"}), which only the unversioned /websocket
	// endpoint accepts. The modern /api/current endpoint speaks pure JSON-RPC 2.0
	// and ignores this handshake -- connecting there just hangs (verified live on
	// 25.10.4). /websocket still works on 25.10 and through Fangtooth. Moving to
	// /api/current is a protocol rewrite, not a URL change; tracked as a known issue.
	return []string{fmt.Sprintf("wss://%s/websocket", net.JoinHostPort(host, port))}, nil
}

func (c *Client) Authenticate() error {
	// Ensure connected before authenticating
	c.connMu.Lock()
	err := c.connect()
	c.connMu.Unlock()
	if err != nil {
		return err
	}

	log.Println("Authenticating with TrueNAS middleware...")

	// auth.login_with_api_key is deprecated in TrueNAS 26 and slated for removal in
	// 27. auth.login_ex (25.04+) is the replacement and still takes an API key, via
	// the API_KEY_PLAIN mechanism -- API keys themselves are not going away, only
	// this login call is. It requires the key's owning username, so fall back to the
	// old call when no username was supplied.
	if c.username != "" {
		result, err := c.callRaw("auth.login_ex", map[string]interface{}{
			"mechanism": "API_KEY_PLAIN",
			"username":  c.username,
			"api_key":   c.apiKey,
		})
		if err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}

		var resp struct {
			ResponseType string `json:"response_type"`
		}
		if err := json.Unmarshal(result, &resp); err != nil {
			return fmt.Errorf("failed to parse authentication response: %w", err)
		}
		if resp.ResponseType != "SUCCESS" {
			// Never include the response body: it can echo credential material.
			return fmt.Errorf("authentication failed: %s", resp.ResponseType)
		}

		c.connMu.Lock()
		c.authenticated = true
		c.connMu.Unlock()

		log.Println("TrueNAS middleware authentication successful (auth.login_ex)")
		return nil
	}

	log.Println("warning: no -username given; falling back to auth.login_with_api_key, " +
		"which is deprecated in TrueNAS 26 and removed in 27")

	result, err := c.callRaw("auth.login_with_api_key", c.apiKey)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	var success bool
	if err := json.Unmarshal(result, &success); err != nil {
		return fmt.Errorf("failed to parse authentication response: %w", err)
	}

	if !success {
		return fmt.Errorf("authentication returned false")
	}

	c.connMu.Lock()
	c.authenticated = true
	c.connMu.Unlock()

	log.Println("TrueNAS middleware authentication successful")
	return nil
}

func (c *Client) Call(method string, params ...interface{}) (json.RawMessage, error) {
	// Ensure connected and authenticated (serialized to prevent concurrent reconnects)
	c.connMu.Lock()
	if err := c.connect(); err != nil {
		c.connMu.Unlock()
		return nil, err
	}
	needsAuth := !c.authenticated
	c.connMu.Unlock()

	if needsAuth {
		if err := c.Authenticate(); err != nil {
			return nil, fmt.Errorf("re-authentication failed: %w", err)
		}
	}

	return c.callRaw(method, params...)
}

// callRaw sends a request and waits for its response via the pending map.
// Safe for concurrent use.
func (c *Client) callRaw(method string, params ...interface{}) (json.RawMessage, error) {
	var lastErr error

	// Try up to 2 times (initial attempt + 1 retry on connection error)
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			log.Printf("Retrying request after connection error (attempt %d/2)...", attempt+1)
			c.connMu.Lock()
			if err := c.connect(); err != nil {
				c.connMu.Unlock()
				return nil, fmt.Errorf("reconnection failed: %w", err)
			}
			c.connMu.Unlock()
			if err := c.Authenticate(); err != nil {
				return nil, fmt.Errorf("re-authentication failed: %w", err)
			}
		}

		// Snapshot the connection under the lock to avoid nil dereference
		c.connMu.Lock()
		conn := c.conn
		c.connMu.Unlock()

		if conn == nil {
			lastErr = fmt.Errorf("not connected")
			if attempt == 0 {
				// Try to reconnect
				c.connMu.Lock()
				if err := c.connect(); err != nil {
					c.connMu.Unlock()
					return nil, fmt.Errorf("reconnection failed: %w", err)
				}
				c.connMu.Unlock()
				if err := c.Authenticate(); err != nil {
					return nil, fmt.Errorf("re-authentication failed: %w", err)
				}
				continue
			}
			return nil, lastErr
		}

		id := fmt.Sprintf("%d", c.requestID.Add(1))

		// Register the response channel BEFORE writing, to avoid a race where
		// the response arrives before we add the channel to the pending map.
		ch := make(chan *responseResult, 1)
		c.pendingMu.Lock()
		c.pending[id] = ch
		c.pendingMu.Unlock()

		req := APIRequest{
			ID:     id,
			Msg:    "method",
			Method: method,
			Params: params,
		}

		if c.debug {
			// Params carry the API key on auth.login_ex; redact before logging.
			reqJSON, _ := json.Marshal(req)
			log.Printf("Sending request: %s", redactForLog(string(reqJSON)))
		}

		// writeMu ensures only one goroutine writes to the WebSocket at a time
		c.writeMu.Lock()
		err := conn.WriteJSON(req)
		c.writeMu.Unlock()

		if err != nil {
			// Remove our pending channel since we failed to send
			c.pendingMu.Lock()
			delete(c.pending, id)
			c.pendingMu.Unlock()

			// Clear the connection if it's still this one
			c.connMu.Lock()
			if c.conn == conn {
				c.conn = nil
				c.authenticated = false
			}
			c.connMu.Unlock()

			lastErr = fmt.Errorf("failed to send request: %w", err)
			if isConnectionError(err) && attempt == 0 {
				continue
			}
			return nil, lastErr
		}

		// Wait for the response router to deliver our response
		select {
		case result := <-ch:
			if result.err != nil {
				lastErr = result.err
				if isConnectionError(result.err) && attempt == 0 {
					continue
				}
				return nil, result.err
			}

			resp := result.resp

			if resp.Msg == "failed" {
				if resp.Error != nil {
					return nil, formatAPIErrorWithContext(resp.Error, method, params)
				}
				return nil, fmt.Errorf("API call failed with no error details")
			}

			if resp.Error != nil {
				return nil, formatAPIErrorWithContext(resp.Error, method, params)
			}

			return resp.Result, nil

		case <-time.After(120 * time.Second):
			// Timeout - clean up pending entry
			c.pendingMu.Lock()
			delete(c.pending, id)
			c.pendingMu.Unlock()
			return nil, fmt.Errorf("request timed out after 120 seconds (method: %s)", method)
		}
	}

	return nil, lastErr
}

// isConnectionError checks if an error is a connection-related error that should trigger a retry
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "EOF") ||
		strings.Contains(errStr, "use of closed network connection") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "i/o timeout") ||
		strings.Contains(errStr, "failed to read response")
}

func (c *Client) Close() error {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	c.authenticated = false
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// formatAPIError formats an API error into a readable error message
func formatAPIError(apiErr *APIError) error {
	errMsg := fmt.Sprintf("API error: %s (code %d)", apiErr.Message, apiErr.Code)
	if apiErr.Trace != nil {
		if traceStr, ok := apiErr.Trace.(string); ok && traceStr != "" {
			errMsg = fmt.Sprintf("%s\nTrace: %s", errMsg, traceStr)
		} else {
			if traceJSON, err := json.MarshalIndent(apiErr.Trace, "", "  "); err == nil {
				errMsg = fmt.Sprintf("%s\nTrace: %s", errMsg, string(traceJSON))
			}
		}
	}
	return fmt.Errorf("%s", errMsg)
}

// formatAPIErrorWithContext formats an API error with request context.
//
// SECURITY: the params it echoes are the request's params -- and for auth.login_ex
// those params ARE the plaintext API key. Upstream serialized them verbatim, so any
// middleware error frame on the auth call (a bad key, a mid-session reconnect that
// re-authenticates and fails) produced an error string containing the key. That
// error reaches two sinks that are not debug-gated: main's log.Fatalf on startup,
// and -- via CallTool's error return -- the model's context and the transcript. The
// debug-log redaction added elsewhere did not cover this path.
//
// So every serialized blob here goes through redactForLog. The Trace is redacted
// too: it is middleware-supplied and can echo the request.
func formatAPIErrorWithContext(apiErr *APIError, method string, params []interface{}) error {
	errMsg := fmt.Sprintf("API error: %s (code %d)", apiErr.Message, apiErr.Code)

	errMsg = fmt.Sprintf("%s\n\nRequest:\n  Method: %s", errMsg, method)

	if len(params) > 0 {
		safe := redactParamsForError(method, params)
		if paramsJSON, err := json.MarshalIndent(safe, "  ", "  "); err == nil {
			errMsg = fmt.Sprintf("%s\n  Params: %s", errMsg, redactForLog(string(paramsJSON)))
		}
	}

	if apiErr.Trace != nil {
		if traceStr, ok := apiErr.Trace.(string); ok && traceStr != "" {
			errMsg = fmt.Sprintf("%s\n\nTrace: %s", errMsg, redactForLog(traceStr))
		} else {
			if traceJSON, err := json.MarshalIndent(apiErr.Trace, "", "  "); err == nil {
				errMsg = fmt.Sprintf("%s\n\nTrace: %s", errMsg, redactForLog(string(traceJSON)))
			}
		}
	}

	return fmt.Errorf("%s", errMsg)
}
