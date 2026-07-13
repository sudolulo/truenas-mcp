# Changelog

All notable changes to this fork are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Version numbers are this fork's own. Upstream ([truenas/truenas-mcp](https://github.com/truenas/truenas-mcp))
last tagged `v0.0.4` in February 2026; its release workflow was removed in July 2026, so builds from
source are the only supported path.

## [Unreleased]

### Fixed (from an independent audit of the fork)

- **HIGH — the API key leaked through the API-error formatter.** `formatAPIErrorWithContext`
  serialized the request's params into the error string, and for `auth.login_ex` those params *are*
  the plaintext key. That path was neither `-debug`-gated nor redacted, so a middleware error frame on
  authentication (bad key, or a mid-session reconnect that re-authenticates and fails) put the key into
  two sinks: `log.Fatalf` at startup, and — via `CallTool`'s error return — the model's context and the
  transcript. The earlier redaction only covered the debug request-*log* frame, which is exactly why
  this survived. Params and the middleware-supplied `Trace` now both go through `redactForLog`.
- **HIGH — the deprecated auth call leaked a *bare positional* key.** `auth.login_with_api_key` passes
  the key as a naked string param with no key name, so key-based redaction could not see it at all.
  `redactParamsForError` now masks every scalar param of any `auth.*` method outright, while leaving
  maps to key-based redaction so useful context (username, mechanism) survives.
- **MEDIUM — redaction was blind to secrets under generic keys.** TrueNAS returns env vars as
  `[{"name":"DB_PASSWORD","value":"hunter2"}]`; the secret sits under `value`, which matches no key
  hint. Redaction now detects the name/value pair shape and masks the value when the *name* looks like
  a credential. Non-secret env vars keep their values.
- **MEDIUM — `bindpw`, `keytab`, and a bare `key` were not masked.** Upstream's `maskCredentials` only
  handles these at the top level, so a nested directory-services credential bypassed both it and
  redaction. Added as hints; bare `key` is an exact-match rule so `keyboard`/`monkey` aren't shredded.
- **`-insecure` was a no-op.** `InsecureSkipVerify` was set unconditionally and the flag only printed a
  log line — certificate verification was *always* off while the flag advertised itself as the thing
  that disabled it. That silently undercut the reason we hard-reject `ws://`: refusing plaintext to
  protect the key means little if the `wss://` connection then trusts any certificate, since an active
  MITM can present one and capture the key during `auth.login_ex`. Verification is now ON by default and
  `-insecure` genuinely disables it, with a warning. **TrueNAS ships a self-signed cert, so `-insecure`
  is required against a stock box** — but it is now an explicit choice, not a silent default.
- **Large integers were corrupted by redaction.** `RedactJSON` unmarshalled into `interface{}`, decoding
  every number as `float64` and silently mangling 64-bit values (a ZFS guid `15032414960031428871` came
  back as `...429000`). Now decodes with `UseNumber()`.
- **Bracketed IPv6 without a port produced a double-bracketed URL** (`wss://[[fd00::1]]:443/...`).

### Known limit (documented, not fixed)

Redaction masks by **key name** (plus the name/value pair shape). A secret embedded inside an opaque
**string blob** — e.g. a custom app's docker-compose YAML returned as one field, with
`POSTGRES_PASSWORD: hunter2` inside it — is **not** caught, because the key holding the blob isn't
credential-shaped and we will not regex the interior of arbitrary strings. `get_app_config` on a
custom/compose app is therefore not fully safe; prefer `query_apps` for those. A test asserts this
current behaviour so it can't be mistaken for safety.

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
- The client speaks the legacy DDP-style protocol over the unversioned `/websocket` endpoint. The
  modern endpoint since 25.04 is `/api/current`, which speaks pure JSON-RPC 2.0 and ignores this
  handshake (connecting there hangs — verified live on 25.10.4). `/websocket` still works on 25.10 and
  through Fangtooth, so this is not urgent, but migrating to `/api/current` is a protocol rewrite of the
  connect/method framing, not a URL change. The port, at least, is no longer hardcoded (see Fixed).
