package truenas

import (
	"encoding/json"
	"strings"
	"testing"
)

// The leak this guards against: the auth.login_ex request frame carries the API
// key in plaintext, and upstream logged every request frame unconditionally. Even
// under -debug the key must never reach a log line.
func TestRedactForLogMasksApiKey(t *testing.T) {
	frame := `{"id":"1","msg":"method","method":"auth.login_ex","params":[{"api_key":"3-SUPERSECRETKEYVALUE","mechanism":"API_KEY_PLAIN","username":"flan"}]}`

	got := redactForLog(frame)

	if strings.Contains(got, "SUPERSECRETKEYVALUE") {
		t.Fatalf("api_key survived log redaction: %s", got)
	}
	// Non-secret fields must remain so the log is still useful.
	for _, keep := range []string{"auth.login_ex", "API_KEY_PLAIN", "flan"} {
		if !strings.Contains(got, keep) {
			t.Errorf("redaction destroyed non-secret field %q: %s", keep, got)
		}
	}
	if !json.Valid([]byte(got)) {
		t.Errorf("redacted log frame is not valid JSON: %s", got)
	}
}

func TestRedactForLogMasksTokensAndPasswords(t *testing.T) {
	frame := `{"result":{"token":"tok_abc","nested":{"password":"pw"}},"other":"keep"}`
	got := redactForLog(frame)
	for _, leaked := range []string{"tok_abc", "\"pw\""} {
		if strings.Contains(got, leaked) {
			t.Errorf("secret %q survived: %s", leaked, got)
		}
	}
	if !strings.Contains(got, "keep") {
		t.Errorf("non-secret was dropped: %s", got)
	}
}

func TestRedactForLogPassesThroughNonJSON(t *testing.T) {
	const s = "Connecting to wss://host:444/websocket..."
	if got := redactForLog(s); got != s {
		t.Errorf("non-JSON log line was mangled: %q", got)
	}
}

// A client with debug off must not log at all; this asserts the gate exists by
// construction (SetDebug false is the zero value), complementing the redaction.
func TestDebugDefaultsOff(t *testing.T) {
	c := &Client{}
	if c.debug {
		t.Error("debug should default to false so verbose logging is off unless asked for")
	}
	c.SetDebug(true)
	if !c.debug {
		t.Error("SetDebug(true) did not enable debug")
	}
}
