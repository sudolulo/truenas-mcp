# Changelog

All notable changes to this fork are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Version numbers are this fork's own. Upstream ([truenas/truenas-mcp](https://github.com/truenas/truenas-mcp))
last tagged `v0.0.4` in February 2026; its release workflow was removed in July 2026, so builds from
source are the only supported path.

## [Unreleased]

## [1.0.0] - 2026-07-12

Forked from upstream at `9acb432`.

### Added

- **`-read-only` flag.** A fail-closed allowlist: the server serves 31 non-mutating tools and refuses
  the remaining 21. Tools that are not explicitly allowlisted — including any that upstream adds in
  future — are refused rather than served. Refused tools are omitted from `tools/list` and rejected at
  dispatch, so a client that names one directly still gets an error.
- **Unconditional secret redaction.** Every tool response is parsed and credential-shaped fields
  (`password`, `token`, `secret`, `encryption_key`, `access_key`, `api_key`, …) are masked before the
  response leaves the server. Applies in read-write mode as well. Responses that are not JSON pass
  through untouched.
- Tests (`tools/readonly_test.go`) asserting that all 21 mutating tools are both hidden and refused,
  that an unknown tool name fails closed, that read-write mode is unaffected, and that a realistic
  `app.config` payload is redacted without destroying non-secret fields. The mutating-tool list is
  asserted against the live registry, so an upstream rename fails the build rather than silently
  widening the boundary.

### Fixed

- **README inaccuracy.** Upstream states "Dry-Run Mode — Preview changes before execution for all
  write operations". Dry-run is opt-in per call; `ExecuteWithDryRun()` falls through to real execution
  when the argument is omitted, and `system_reboot` registers an empty input schema so it accepts no
  arguments at all. The documentation now describes the actual behaviour and points to `-read-only`
  for a real boundary.

### Known issues (inherited from upstream, not yet addressed)

- `auth.login_with_api_key` is deprecated in TrueNAS 26 and slated for removal in 27; the replacement
  is `auth.login_ex`. Works on Fangtooth; will break on a later upgrade.
- The WebSocket endpoint is hardcoded to the legacy `wss://<host>:443/websocket` path. The modern
  endpoint since 25.04 is `/api/current` (JSON-RPC 2.0). There is no flag to select the path, only to
  pass a whole URL.
