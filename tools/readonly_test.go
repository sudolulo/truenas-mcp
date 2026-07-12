package tools

import (
	"encoding/json"
	"strings"
	"testing"
)

// The tools that must never be reachable in read-only mode. system_reboot is the
// motivating case: upstream registers it with an empty input schema and a handler
// that calls system.reboot immediately, so a single tool call takes the host down.
var mustBeRefused = []string{
	"system_reboot",
	"apply_update",
	"download_update",
	"delete_app",
	"delete_boot_environment",
	"delete_scrub_schedule",
	"install_app",
	"update_app",
	"upgrade_app",
	"start_app",
	"stop_app",
	"create_dataset",
	"create_nfs_share",
	"create_smb_share",
	"create_scrub_schedule",
	"run_scrub",
	"configure_directory_service",
	"leave_directory_service",
	"refresh_directory_cache",
	"dismiss_alert",
	"restore_alert",
}

func readOnlyRegistry(t *testing.T) *Registry {
	t.Helper()
	// A nil client is fine: every assertion below is refused before dispatch.
	r := NewRegistry(nil, nil)
	r.SetReadOnly(true)
	return r
}

func TestReadOnlyRefusesMutatingTools(t *testing.T) {
	r := readOnlyRegistry(t)
	for _, name := range mustBeRefused {
		if _, ok := r.tools[name]; !ok {
			t.Fatalf("%s is not registered upstream any more — this test is stale", name)
		}
		if _, err := r.CallTool(name, map[string]interface{}{}); err == nil {
			t.Errorf("CallTool(%q) succeeded in read-only mode; it must be refused", name)
		}
	}
}

func TestReadOnlyHidesMutatingToolsFromListing(t *testing.T) {
	r := readOnlyRegistry(t)
	listed := make(map[string]bool)
	for _, tool := range r.ListTools() {
		listed[tool.Name] = true
	}
	for _, name := range mustBeRefused {
		if listed[name] {
			t.Errorf("ListTools() advertises %q in read-only mode; the model must not see it", name)
		}
	}
	if len(listed) == 0 {
		t.Fatal("read-only mode listed no tools at all")
	}
}

// Fail closed: a tool upstream adds later, that we have not reviewed, must be
// refused rather than silently served.
func TestReadOnlyIsFailClosedForUnknownTools(t *testing.T) {
	r := readOnlyRegistry(t)
	if r.allowed("some_tool_upstream_adds_next_year") {
		t.Error("an unreviewed tool was allowed; the allowlist is not fail-closed")
	}
}

func TestReadWriteModeAllowsEverything(t *testing.T) {
	r := NewRegistry(nil, nil)
	if !r.allowed("system_reboot") {
		t.Error("read-only gating leaked into read-write mode")
	}
	if len(r.ListTools()) != r.ToolCount() {
		t.Error("ListTools() filtered tools while not in read-only mode")
	}
}

// A realistic app.config payload — this is the shape that has leaked before.
func TestRedactJSONMasksCredentials(t *testing.T) {
	payload := `{
	  "app_name": "immich",
	  "config": {
	    "db_password": "hunter2",
	    "encryption_key": "aabbccdd",
	    "redis_password": "swordfish",
	    "API_TOKEN": "tok_live_123",
	    "postgres": {"POSTGRES_PASSWORD": "nested-secret"},
	    "env": [{"name": "X", "access_key": "AKIA..."}],
	    "port": 30041,
	    "enabled": true
	  }
	}`

	got := RedactJSON(payload)

	for _, leaked := range []string{"hunter2", "aabbccdd", "swordfish", "tok_live_123", "nested-secret", "AKIA..."} {
		if strings.Contains(got, leaked) {
			t.Errorf("secret %q survived redaction", leaked)
		}
	}
	// Non-secret fields must be preserved, or the tool is useless.
	for _, keep := range []string{"immich", "30041"} {
		if !strings.Contains(got, keep) {
			t.Errorf("non-secret value %q was destroyed by redaction", keep)
		}
	}
	var v interface{}
	if err := json.Unmarshal([]byte(got), &v); err != nil {
		t.Fatalf("redacted output is not valid JSON: %v", err)
	}
}

func TestRedactJSONPassesThroughNonJSON(t *testing.T) {
	const plain = "pool ok, 3 datasets"
	if got := RedactJSON(plain); got != plain {
		t.Errorf("non-JSON response was mangled: %q", got)
	}
}
