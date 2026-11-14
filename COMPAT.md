# Compatibility registry

Every wire, API or storage format that older or newer releases must still read, per the
breaking-change procedure (compat rules section P, `docs/compat-rules.md`).
A change that is not purely additive gets a row here before it merges.

Columns:
- **What** — the format, field, code or header.
- **Cap** — the capability peers or clients choose by (`—` if none; `PROTOCOL_VERSION` is the epoch).
- **Reader in** — releases that read it.
- **Write gate** — the condition under which writers may emit it (W7).
- **Removal epoch** — earliest epoch that may drop the reader (`—` = never planned).
- **Reason** — why it exists.

## 1.0 baseline (epoch 1)

| What | Cap | Reader in | Write gate | Removal epoch | Reason |
|------|-----|-----------|------------|---------------|--------|
| Action-token `crit` claim (array of content fields, `$claim`, `$f:<char>`) | — | 1.0+ | none (baseline) | — | Lets a writer mark must-understand additions; unknown names are refused 422 `E-FED-UNSUPPORTED` |
| `ES384:<spki-base64>` public-key prefix (unprefixed = ES384) | — | 1.0+ | none (baseline) | — | Algorithm agility; an unknown prefix is "unsupported", not a forgery |
| `E-FED-UNSUPPORTED` (422 on `/api/inbox`, `/api/inbox/sync`, local `POST /api/actions`) | — | 1.0+ | none (baseline) | — | Unknown type, unlisted subtype, unknown `crit` name or key algorithm, distinct from a forgery |
| `ActionView.deliveryError: "unsupported"` | — | 1.0+ | none (baseline) | — | Shows the sender that a recipient refused the action as unsupported |
| File descriptor `d2,` (writer); legacy `d1~` still parsed | — | 1.0+ (`d1~` reader: 1.0+) | `d2,` always written | `d1~` reader: epoch 2 | `crates/cloudillo-file/src/descriptor.rs`; `d1~` only from pre-1.0 data |
| Error codes `E-REF-EXPIRED`, `E-REF-USED`, `E-IDP-NOTPENDING` | — | 1.0+ | none (baseline) | — | Distinguish expired / used refs and non-pending IDP identities (`crates/cloudillo-types/src/error.rs`) |
| RTDB unknown command → error frame `data.code: "E-RTDB-UNKNOWNCOMMAND"` (was numeric `code: 501`) | — | 1.0+ | none (baseline) | — | Clients detect a command the server does not know (`crates/cloudillo-types/src/error.rs`) |
| `X-Cloudillo-Version` response header on `/api` (CORS-exposed) | — | 1.0+ | none (baseline) | — | Clients and peers detect the serving release (`crates/cloudillo/src/routes/policy.rs`) |
