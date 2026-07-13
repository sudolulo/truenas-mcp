package tools

import (
	"bytes"
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
//
// KNOWN LIMIT, stated plainly: this masks by KEY NAME (plus the name/value pair
// shape below). A secret embedded inside an opaque string -- e.g. a custom app's
// docker-compose YAML returned as one blob, with `POSTGRES_PASSWORD: hunter2`
// inside it -- is NOT caught, because the key holding the blob isn't credential-
// shaped and we will not regex the interior of arbitrary strings. get_app_config on
// a custom/compose app is therefore not fully safe; prefer query_apps for those.

const redactedMarker = "***REDACTED***"

// secretKeyHints are matched case-insensitively as SUBSTRINGS of the JSON key.
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
	// TrueNAS-specific: directory-services bind password and Kerberos keytab.
	// Upstream's maskCredentials only masks these at the TOP level, so a nested
	// credential object slipped through both it and this.
	"bindpw",
	"keytab",
}

// exactSecretKeys are matched case-insensitively as WHOLE keys. Kept separate from
// the substring list so a bare "key" is caught without also masking "keyboard",
// "monkey", or "key_count".
var exactSecretKeys = map[string]bool{
	"key":  true,
	"pw":   true,
	"pass": true,
}

func looksSecret(key string) bool {
	k := strings.ToLower(key)
	if exactSecretKeys[k] {
		return true
	}
	for _, hint := range secretKeyHints {
		if strings.Contains(k, hint) {
			return true
		}
	}
	return false
}

// envPairSecret handles the {"name": "DB_PASSWORD", "value": "hunter2"} shape used
// for environment variables. The secret sits under the generic key "value", which
// no key-name rule would ever catch -- the credential-ness lives in the sibling's
// *value*, not in the key. If a map carries a name-ish field whose value looks like
// a credential identifier, mask its value-ish field.
func envPairSecret(m map[string]interface{}) bool {
	for _, nameKey := range []string{"name", "key", "variable", "env"} {
		if raw, ok := m[nameKey]; ok {
			if s, ok := raw.(string); ok && looksSecret(s) {
				return true
			}
		}
	}
	return false
}

// redactValue walks a decoded JSON tree, masking any value whose key looks
// secret-bearing. Nested maps and arrays are walked; scalars are passed through.
func redactValue(v interface{}) interface{} {
	switch node := v.(type) {
	case map[string]interface{}:
		maskValueField := envPairSecret(node)
		out := make(map[string]interface{}, len(node))
		for key, val := range node {
			if looksSecret(key) {
				out[key] = redactedMarker
				continue
			}
			// {"name":"DB_PASSWORD","value":"hunter2"} -> mask "value"
			if maskValueField && strings.EqualFold(key, "value") {
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
//
// Numbers are decoded with UseNumber so large integers survive the round-trip. A
// plain unmarshal turns every number into a float64, which silently mangles 64-bit
// values (a ZFS guid like 15032414960031428871 came back as ...429000).
func RedactJSON(s string) string {
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()

	var decoded interface{}
	if err := dec.Decode(&decoded); err != nil {
		return s
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(redactValue(decoded)); err != nil {
		return s
	}
	return strings.TrimRight(buf.String(), "\n")
}
