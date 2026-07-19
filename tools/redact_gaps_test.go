package tools

import (
	"strings"
	"testing"
)

// The audit's MEDIUM-HIGH finding: RedactJSON masked by key name only, so a secret
// sitting under the generic key "value" (the {"name":"DB_PASSWORD","value":"..."}
// env-var shape TrueNAS uses) sailed straight through. The original test used
// {"name":"X","access_key":"AKIA..."} -- a hint-matched key -- which is exactly why
// the gap survived.
func TestRedactJSONMasksEnvNameValuePairs(t *testing.T) {
	payload := `{
	  "config": {
	    "environment": [
	      {"name": "DB_PASSWORD", "value": "hunter2"},
	      {"name": "REDIS_TOKEN",  "value": "tok_abc"},
	      {"name": "TZ",           "value": "America/New_York"}
	    ]
	  }
	}`
	got := RedactJSON(payload)

	for _, leaked := range []string{"hunter2", "tok_abc"} {
		if strings.Contains(got, leaked) {
			t.Errorf("secret %q survived under the generic \"value\" key:\n%s", leaked, got)
		}
	}
	// A non-secret env var must keep its value, or the tool is useless.
	if !strings.Contains(got, "America/New_York") {
		t.Errorf("non-secret env value was destroyed:\n%s", got)
	}
	// The names themselves stay visible -- knowing DB_PASSWORD *exists* is useful.
	if !strings.Contains(got, "DB_PASSWORD") {
		t.Errorf("env var name should survive:\n%s", got)
	}
}

// The audit's MEDIUM finding: TrueNAS directory-services credentials (bindpw,
// keytab) matched no hint, and upstream's maskCredentials only masks them at the
// TOP level -- so a nested one bypassed both.
func TestRedactJSONMasksTrueNASDirectoryCredentials(t *testing.T) {
	payload := `{"credential": {"bindpw": "ldapsecret", "keytab": "BASE64KEYTAB", "binddn": "cn=admin"}}`
	got := RedactJSON(payload)
	for _, leaked := range []string{"ldapsecret", "BASE64KEYTAB"} {
		if strings.Contains(got, leaked) {
			t.Errorf("directory-services secret %q survived:\n%s", leaked, got)
		}
	}
}

// A bare "key" is a credential; "keyboard"/"monkey" are not. Exact-match, not
// substring, so we don't shred harmless fields.
func TestRedactJSONBareKeyExactMatchOnly(t *testing.T) {
	got := RedactJSON(`{"key": "s3cret", "keyboard_layout": "us", "monkey_count": 3}`)
	if strings.Contains(got, "s3cret") {
		t.Errorf("bare \"key\" was not masked:\n%s", got)
	}
	if !strings.Contains(got, "us") || !strings.Contains(got, "3") {
		t.Errorf("over-redacted a harmless key containing \"key\":\n%s", got)
	}
}

// The audit's LOW/INFO finding: unmarshalling into interface{} decodes every number
// as float64, silently mangling 64-bit integers. A ZFS guid came back wrong.
func TestRedactJSONPreservesLargeIntegers(t *testing.T) {
	const guid = "15032414960031428871"
	got := RedactJSON(`{"guid": ` + guid + `, "size": 9007199254740993}`)
	if !strings.Contains(got, guid) {
		t.Errorf("64-bit guid was corrupted by the float64 round-trip:\n%s", got)
	}
	if !strings.Contains(got, "9007199254740993") {
		t.Errorf("integer past 2^53 was corrupted:\n%s", got)
	}
}

// Previously the audit's honestly-documented gap: a secret inside an opaque string
// blob (a custom app's compose YAML) sailed through because redaction masked by key
// name only. redactStringBlob now scans the interior of string values, so this is
// covered -- a POSTGRES_PASSWORD embedded in a compose blob must be masked, while a
// non-secret line in the same blob survives.
func TestRedactJSONMasksSecretsInsideStringBlobs(t *testing.T) {
	got := RedactJSON(`{"custom_compose_config_string": "services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: hunter2\n      TZ: America/New_York\n    ports:\n      - 5432:5432\n"}`)
	if strings.Contains(got, "hunter2") {
		t.Errorf("secret inside a compose-YAML string blob survived:\n%s", got)
	}
	// The compose-list dotenv form (- KEY=value) must also be caught.
	got2 := RedactJSON(`{"env_blob": "FOO=bar\nAPI_TOKEN=sk_live_deadbeef\n"}`)
	if strings.Contains(got2, "sk_live_deadbeef") {
		t.Errorf("secret inside a KEY=value env blob survived:\n%s", got2)
	}
	// Non-secret lines, and structural YAML, must be left intact.
	for _, keep := range []string{"America/New_York", "services:", "5432:5432", "bar"} {
		if !strings.Contains(got+got2, keep) {
			t.Errorf("blob scan destroyed a non-secret line %q:\n%s\n%s", keep, got, got2)
		}
	}
}
