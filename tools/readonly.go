package tools

// Read-only mode.
//
// readOnlyTools is a FAIL-CLOSED allowlist: with -read-only the server serves
// exactly these tools and refuses everything else, including tools that do not
// exist yet. A denylist of known-mutating names would silently admit whatever
// upstream registers next -- and upstream ships tools like system_reboot, whose
// input schema is empty (no dry_run, no confirmation) and whose handler calls
// system.reboot immediately. On a box that hosts every service we run, one
// unconfirmed tool call is not an acceptable failure mode.
//
// Upstream's dry_run is opt-in per call: tools/dryrun.go falls through to real
// execution when the model simply omits the argument. That makes it a hint, not
// a boundary. This is the boundary.
var readOnlyTools = map[string]bool{
	"analyze_capacity":             true,
	"check_updates":                true,
	"get_app_catalog_details":      true,
	"get_arc_metrics":              true,
	"get_current_boot_environment": true,
	"get_directory_service_status": true,
	"get_disk_metrics":             true,
	"get_network_metrics":          true,
	"get_pool_capacity_details":    true,
	"get_scrub_status":             true,
	"get_system_metrics":           true,
	"get_ups_metrics":              true,
	"list_alerts":                  true,
	"list_directory_certificates":  true,
	"query_apps":                   true,
	"query_boot_environments":      true,
	"query_datasets":               true,
	"query_directory_services":     true,
	"query_jobs":                   true,
	"query_pools":                  true,
	"query_scrub_schedules":        true,
	"query_shares":                 true,
	"query_snapshots":              true,
	"query_vms":                    true,
	"search_app_catalog":           true,
	"system_health":                true,
	"system_info":                  true,
	"tasks_get":                    true,
	"tasks_list":                   true,

	// update.status reports what updates are available; it does not apply them.
	// (apply_update, download_update and update_app are all mutating and absent.)
	"update_status": true,

	// Reads app.config, which returns the app's full configuration map --
	// database passwords, encryption keys, API tokens and all. It is genuinely
	// read-only, so it belongs here, but it is only safe because every response
	// goes through RedactJSON in CallTool. Do not add a caller that bypasses it.
	"get_app_config": true,
}

// SetReadOnly enables or disables read-only mode.
func (r *Registry) SetReadOnly(ro bool) { r.readOnly = ro }

// ReadOnly reports whether read-only mode is active.
func (r *Registry) ReadOnly() bool { return r.readOnly }

// ToolCount is the number of registered tools, before any read-only filtering.
func (r *Registry) ToolCount() int { return len(r.tools) }

// allowed reports whether a tool may be listed or invoked in the current mode.
func (r *Registry) allowed(name string) bool {
	if !r.readOnly {
		return true
	}
	return readOnlyTools[name]
}
