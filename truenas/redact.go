package truenas

import (
	"encoding/json"
	"strings"
)

// Defense in depth for debug logging. The wire protocol carries the API key in
// auth.login_ex params and session tokens in auth responses. Verbose logging is
// gated behind -debug, but a developer turning on -debug to diagnose a connection
// must not thereby write their credential to a file. So even under -debug the
// logged JSON is redacted.
//
// This is deliberately separate from tools.RedactJSON: tools imports truenas, so
// truenas cannot import tools. The two guard different surfaces (tool responses to
// the model vs. debug logs to stderr) and are independent by design.

var logSecretKeys = []string{
	"api_key", "apikey", "password", "passwd", "passphrase",
	"secret", "token", "credential", "private_key", "privatekey",
	// TrueNAS directory-services: bind password and Kerberos keytab.
	"bindpw", "keytab",
}

// Whole-key matches, so a bare "key" is caught without masking "keyboard".
var logExactSecretKeys = map[string]bool{"key": true, "pw": true, "pass": true}

func logKeyIsSecret(k string) bool {
	k = strings.ToLower(k)
	if logExactSecretKeys[k] {
		return true
	}
	for _, h := range logSecretKeys {
		if strings.Contains(k, h) {
			return true
		}
	}
	return false
}

func redactLogValue(v interface{}) interface{} {
	switch n := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(n))
		for k, val := range n {
			if logKeyIsSecret(k) {
				out[k] = "***REDACTED***"
			} else {
				out[k] = redactLogValue(val)
			}
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(n))
		for i, val := range n {
			out[i] = redactLogValue(val)
		}
		return out
	default:
		return v
	}
}

// redactParamsForError sanitises a request's params before they are echoed into an
// error string.
//
// redactForLog masks by KEY NAME, which covers auth.login_ex (whose params are a map
// containing "api_key"). But the deprecated auth.login_with_api_key passes the key as
// a BARE POSITIONAL param -- a naked string with no key at all -- so key-based
// redaction cannot see it, and it leaked verbatim. For any auth.* method every scalar
// param is credential material by definition, so mask them outright. Map/array params
// are left for redactForLog, which preserves useful context (username, mechanism).
func redactParamsForError(method string, params []interface{}) []interface{} {
	isAuth := strings.HasPrefix(strings.ToLower(method), "auth.")
	out := make([]interface{}, len(params))
	for i, p := range params {
		switch p.(type) {
		case map[string]interface{}, []interface{}:
			out[i] = p // key-based redaction handles these after marshalling
		default:
			if isAuth {
				out[i] = "***REDACTED***"
			} else {
				out[i] = p
			}
		}
	}
	return out
}

// redactForLog masks credential-shaped fields in a JSON document for safe logging.
// Non-JSON input is returned as-is so a log line is never silently dropped.
func redactForLog(s string) string {
	var decoded interface{}
	if err := json.Unmarshal([]byte(s), &decoded); err != nil {
		return s
	}
	out, err := json.Marshal(redactLogValue(decoded))
	if err != nil {
		return s
	}
	return string(out)
}
