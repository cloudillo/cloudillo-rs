# Changelog

All notable changes to Cloudillo are listed here. The server (`cloudillo-rs`), the web client
(`cloudillo`), the container image and the crates share one version number `X.Y.Z`. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); how releases are cut is in
[README.md](README.md#releasing).

Every release has a **Security** section: security fixes and hardening, with links to the
advisories published under this repository's
[GitHub security advisories](https://github.com/cloudillo/cloudillo-rs/security/advisories)
as described in [SECURITY.md](SECURITY.md). `release.sh` refuses a tag whose version has
no section here.

## [0.8.22] - 2026-10-30

### Security
- Audit log of authentication and administration events (auth DB v7): `GET /api/auth/audit` for
  the tenant, `GET /api/admin/audit` and `GET /api/admin/audit.csv` for the administrator.
- TOTP two-factor authentication, enforceable with the `auth.mfa` setting (auth DB v8).
- Tenant suspension and expiry (auth DB v9).
- Content-Security-Policy on API JSON responses.
- Registration can be switched off.
- The shell and published sites send a Content-Security-Policy without
  `script-src 'unsafe-inline'`; the inline boot script moved to `/assets-<ver>/boot.js`.
- Pinned supply chain: base images by digest, source tarballs checked by SHA-256, pnpm by exact
  version, frontend installs with `--frozen-lockfile` only, CI actions by commit SHA.
  `deny.toml` (licences, bans, sources) checked by `cargo deny check`; a coverage report in
  CI; native image components listed in `sbom/native-components.cdx.json`.
- Signed releases: `release.sh` builds the image from the tag, publishes CycloneDX SBOMs and
  test evidence, and signs the image, the SBOM attestation and `SHA256SUMS` with the project's
  `cosign` key (`cosign.pub`). Verification steps are in [DOCKER.md](DOCKER.md#verifying-a-release).
- [SECURITY.md](SECURITY.md): vulnerability reporting, coordinated disclosure, supported versions.
- `auth.session_timeout` (default 24 h) is enforced through the `auth_time` claim, including
  for API-key chains and QR approval: once it runs out the session cannot be renewed and the
  user is logged out. API keys store their creator's login time (auth DB v10).
- `auth.remember_days` (default 30, 0 disables) limits the lifetime of unscoped API keys.
- Security alert e-mails to `audit.alert_email`: ban, MFA reset, suspension, purge, global
  settings change, failed backup, repeated login failures. A change of the address is also
  reported to the previous address.
- Federation peer policy `federation.peers`: open, allowlist or off, with `*.domain` wildcards.
- DNSSEC validation of federation DNS, opt-in via `ENABLE_DNSSEC` (needs a resolver that
  passes DNSSEC records).
- Server-wide push switch `notify.push_allowed`.
- The storage quota `limits.max_storage_gb` is enforced (507 `E-FILE-QUOTA`).

### Added
- Online backup: per-store consistent snapshots (taken one after another) into `BACKUP_DIR`
  (default `$DATA_DIR/backup`), daily at `backup.time`
  (keeping `backup.keep` snapshots) or on demand with `POST /api/admin/backup`; status at
  `GET /api/admin/backup`. Offline restore with `cloudillo restore <snapshot-dir> [--force]`.
  See [DOCKER.md](DOCKER.md#backup-and-restore).
- Release script `release.sh` and this changelog.
- Trash auto-purge after `file.trash_retention_days` (default 30). **Existing trash older than
  30 days is purged on the first start.**
- `onboarding.community` and `map.tile_sources` settings.
- `GET /.well-known/cloudillo/tenant`: on-demand TLS `ask` endpoint for a reverse proxy.

### Changed
- Licence: MPL-2.0.
- A second server on the same `DB_DIR` refuses to start (lock file `DB_DIR/cloudillo.lock`).
- The Dockerfile builds release tags (`RS_REF` / `FRONTEND_REF` default to the release tag);
  `OPALUI_REF` is gone, opalui comes from npm, pinned by the frontend lockfile.
- `MODE=proxy` serves plain HTTP and does no ACME work.
- Idle CRDT documents are evicted from memory.
- A peer protocol mismatch is recorded in the audit log.

## [0.8.21] - 2026-10-20

First version listed in this changelog; earlier changes are in the git history.

### Security
- Not tracked before this changelog; see the git history.
