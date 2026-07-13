package truenas

import (
	"strings"
	"testing"
)

// The HIGH finding from the audit: formatAPIErrorWithContext serialized the request
// params into the error string, and for auth.login_ex those params ARE the plaintext
// API key. That error is not debug-gated and reaches log.Fatalf on startup and, via
// CallTool's error return, the model's context. The original redaction test only
// covered the debug request-LOG frame, which is precisely why this path survived.
func TestAPIErrorDoesNotLeakApiKey(t *testing.T) {
	const key = "3-SUPERSECRETKEYVALUE"
	params := []interface{}{
		map[string]interface{}{
			"mechanism": "API_KEY_PLAIN",
			"username":  "flan",
			"api_key":   key,
		},
	}
	apiErr := &APIError{Code: 1, Message: "authentication failed"}

	err := formatAPIErrorWithContext(apiErr, "auth.login_ex", params)
	got := err.Error()

	if strings.Contains(got, key) {
		t.Fatalf("API key leaked into the error string:\n%s", got)
	}
	if !strings.Contains(got, "REDACTED") {
		t.Errorf("expected the key to be masked, got:\n%s", got)
	}
	// Diagnostics must survive, or the error is useless.
	for _, keep := range []string{"auth.login_ex", "authentication failed", "flan"} {
		if !strings.Contains(got, keep) {
			t.Errorf("redaction destroyed useful context %q:\n%s", keep, got)
		}
	}
}

// The deprecated fallback passes the key as a bare positional param, not inside a
// map. Make sure that shape is masked too.
func TestAPIErrorDoesNotLeakBarePositionalKey(t *testing.T) {
	const key = "3-BAREPOSITIONALKEY"
	err := formatAPIErrorWithContext(
		&APIError{Code: 1, Message: "bad key"}, "auth.login_with_api_key", []interface{}{key})
	if strings.Contains(err.Error(), key) {
		t.Errorf("bare positional API key leaked into the error string:\n%s", err.Error())
	}
}

// The middleware-supplied Trace can echo the request back at us.
func TestAPIErrorRedactsTrace(t *testing.T) {
	const key = "3-TRACELEAKEDKEY"
	apiErr := &APIError{
		Code:    1,
		Message: "boom",
		Trace:   map[string]interface{}{"request": map[string]interface{}{"api_key": key}},
	}
	err := formatAPIErrorWithContext(apiErr, "auth.login_ex", nil)
	if strings.Contains(err.Error(), key) {
		t.Errorf("API key leaked via Trace:\n%s", err.Error())
	}
}
