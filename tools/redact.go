package tools

import (
	"encoding/json"
	"strings"
)

// Secret redaction.
//
// TrueNAS middleware responses are secret-bearing by default. app.config in
// particular returns an app's entire configuration -- db passwords, encryption
// keys, redis passwords, API tokens -- and upstream's handleGetAppConfig returns
// that map verbatim. Anything an MCP tool returns lands in a model's context and,
// from there, in a transcript that persists indefinitely. Treat every response as
// if it contains a credential, because in practice it does.
//
// So redaction is unconditional: it runs in read-write mode too. There is no
// legitimate reason for a credential to reach the model, and "the operator
// remembered to field-filter" is not a control.

const redactedMarker = "***REDACTED***"

// secretKeyHints are matched case-insensitively as substrings of the JSON key.
// Over-redaction is the safe failure here; under-redaction is not.
var secretKeyHints = []string{
	"password",
	"passwd",
	"passphrase",
	"secret",
	"token",
	"apikey",
	"api_key",
	"credential",
	"private_key",
	"privatekey",
	"encryption_key",
	"access_key",
}

func looksSecret(key string) bool {
	k := strings.ToLower(key)
	for _, hint := range secretKeyHints {
		if strings.Contains(k, hint) {
			return true
		}
	}
	return false
}

// redactValue walks a decoded JSON tree, masking any value whose key looks
// secret-bearing. Nested maps and arrays are walked; scalars are passed through.
func redactValue(v interface{}) interface{} {
	switch node := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(node))
		for key, val := range node {
			if looksSecret(key) {
				out[key] = redactedMarker
				continue
			}
			out[key] = redactValue(val)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(node))
		for i, val := range node {
			out[i] = redactValue(val)
		}
		return out
	default:
		return v
	}
}

// RedactJSON masks credential-looking fields in a JSON document. Input that is
// not valid JSON is returned unchanged -- redaction must never destroy a
// response it does not understand.
func RedactJSON(s string) string {
	var decoded interface{}
	if err := json.Unmarshal([]byte(s), &decoded); err != nil {
		return s
	}
	out, err := json.MarshalIndent(redactValue(decoded), "", "  ")
	if err != nil {
		return s
	}
	return string(out)
}
