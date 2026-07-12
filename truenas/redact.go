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
}

func logKeyIsSecret(k string) bool {
	k = strings.ToLower(k)
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
