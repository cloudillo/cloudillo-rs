# Cross-version compatibility rules (effective from 1.0)

Background and rationale: `claude-docs/version-compat/prd.md` (r3). Unknown actions:
`claude-docs/version-compat/unknown-actions-decision.md` (dropped with 422).

**Window.** All supported releases (latest patch of: N, N-1, current LTS, previous LTS during its
6-month overlap) must interoperate. Worst-case gap is about 2.5 years. Every rule below is
judged against the **oldest supported release**.

**Vocabulary**
- *Epoch*: `PROTOCOL_VERSION`. Bumped only at an LTS. Epoch E speaks E-1.
- *Cap*: a feature string in `/me.caps` (`api:`, `ws:`, `app:`). Not shipped in 1.0; a missing
  `caps` means baseline. Action types are never caps.
- *Transport-level*: chosen per peer (endpoint, envelope). *Token-level*: inside a signed token,
  or content-addressed, fanned out to many peers.
- *Unsupported*: an unknown type, unlisted subtype or unknown `crit` name. Refused with 422
  `E-FED-UNSUPPORTED`, nothing stored.

## W — Wire: action tokens

- **W1** Never remove, rename or re-mean a claim or content field. A new meaning gets a new name.
- **W2** New content fields are optional. If ignoring a field, claim or restriction flag would
  misrepresent the action (a content warning, expiry, audience restriction, `nbf`), list it in
  `crit` (`field`, `$claim`, `$f:<char>`).
- **W3** A new type or subtype is refused by every older supported node (422). Its feature
  must degrade to "not delivered" for directed actions and to absence for broadcast ones; design
  the UX for that.
- **W4** Unknown enum values fail closed: visibility → `Direct`, role → lowest, profile type →
  most restricted, flag → capability off. Never map an unknown value to something more
  permissive. A new *restriction* flag goes in `crit` (flags are opt-out).
- **W5** A new subtype must be listed in its base type's `subtypes` map (or have its own
  definition); the maps are authoritative and checked at startup. Older nodes refuse unlisted
  subtypes, so they never get base-type handling.
- **W6** Hook / state-machine behavior of an existing type (CONN, FLLW, invites…) is protocol.
  Changing it follows the expand/contract procedure (P).
- **W7** Token-level format changes are **release-gated**: write them only once every supported
  line's latest patch reads them. Never caps-gated. Token-level covers:
  - claims and content shape;
  - signature algorithm;
  - id derivation and hash prefixes;
  - the file descriptor grammar;
  - proxy-token scopes;
  - relaxing a per-type rule (`Forbidden`, `allow_hat`, `local_only`).
- **W8** Signature / key changes: verify-first, sign-later. Keys carry their algorithm as a
  prefix (`ES384:<spki>`; unprefixed = ES384). An unknown prefix is "unsupported", not a forgery.
- **W9** Inbound validation may be tightened only for shapes **no supported release emits**.
  (This replaces the alpha-stage note in CLAUDE.md after 1.0.)
- **W10** Limits are protocol in both directions. A sender stays within the inbound caps of the
  oldest supported release. Raising a cap follows P: raise the reader first, the writer once the
  gate is met. This covers the object size cap, `max_length`, enum lists, `MAX_RELATED_TOKENS`
  and attachment counts.
- **W11** `v` (visibility) is one char forever.
- **W12** `E-FED-UNSUPPORTED` (422) and the `deliveryError` marker are protocol.

## I — Inbound processing

- **I1** An unknown type, an unlisted subtype or an unknown `crit` name is refused with 422
  before anything is stored (inside `related` and history sync it is skipped one by one).
- **I2** Side effects are selected by `ctx.effects()`, never by checking the origin or adding
  per-caller flags. New side-effect sites take `Effects` as a required argument.
- **I3** The `Backfill` origin never notifies, forwards live, or propagates. Key replacement is
  newer-wins (`created_at`) for every origin.
- **I4** Federation status contract: 4xx = terminal, 429/503 = retry with `Retry-After`,
  `E-FED-UNSUPPORTED` = valid but not understood. Never map a transient failure to a
  permission outcome.

## A — REST and WebSocket API

- **A1** Additive only: new endpoints, new optional request fields, new response fields, new
  WS message types.
- **A2** Never remove, rename or retype a response key. Never make an optional request field
  required. Never change the error code for an existing condition (clients branch on codes).
- **A3** A breaking change gets a new name. The old one stays until every supported release
  that calls it is EOL. Track it in `COMPAT.md`.
- **A4** A feature a client may use **on a remote node** is detectable (cap, or a documented
  fallback on `E-CORE-NOROUTE`). The client checks before showing the feature. The release
  that adds the first post-1.0 remote feature introduces caps (missing = baseline).
- **A5** Tolerant reader:
  - Clients and servers ignore unknown fields, enum values and WS message types.
  - Never `deny_unknown_fields` on anything another node or client sends, and no closed enums in
    request extractors.
  - Clients decode enums as open (unknown → `'unknown'`, fail closed at the use site) and decode
    lists per item.
- **A6** CRDT: the Yjs update encoding is part of the protocol. Yjs/yrs are pinned; a bump or
  encoding switch follows P. RTDB / bus protocols follow A1–A5.
- **A7** Proxy-token scopes, claims, query names and response shapes are protocol (W1, W7 apply).
- **A8** Errors are distinguished by code, never by message text.
- **A9** An unknown route returns `E-CORE-NOROUTE`, distinct from a missing resource.

## C — Shared documents (CRDT)

- **C1** Every Y.Doc carries `meta.schema` (minimum reader version). An app opens a document
  with a higher schema read-only.
- **C2** Converters preserve unknown keys and codes and render unknown types as placeholders.
  They never throw on unknown data.
- **C3** A destructive document migration follows P.
- **C4** Each app has a golden document corpus in CI.

## S — Apps and SDK

- **S1** The app bus and `@cloudillo/*` follow A1–A5. Bus payload enums are open; unknown
  requests get `E-BUS-UNKNOWN`. The envelope `v` is frozen.
- **S2** An app's manifest declares the caps it needs in `requires.shell` / `requires.doc`. The
  shell checks `shell` against the home node and `doc` against the document's node. In 1.0
  (no caps yet), `install_app` refuses any non-empty `requires.shell`; `requires.doc` checking
  ships with caps.
- **S3** SDK semver versions the bus + client surface only, decoupled from the platform version.
  Major bumps happen only at an LTS.
- **S4** Server-injected policies that the frontend mirrors (sandbox, CSP) come from one source
  or are cross-checked by a test.

## D — Data and upgrades

- **D1** An upgrade from any supported release to any newer one works in one step. Keep
  migrations back to the oldest supported upgrade source. CI diffs the fresh schema against one
  migrated from each checked-in fixture (`tests/fixtures/*.db`).
- **D2** Stored foreign tokens are immutable. Migrations may add derived columns, never
  rewrite the token.
- **D3** No downgrade path is promised, but **D4** the binary refuses a DB (SQL or redb) newer
  than itself, and an unreadable schema version is an error.
- **D5** Migrations never call live adapter or domain code; their logic is frozen.
- **D6** Serialized formats (scheduler task input, settings values, JSON columns, redb records)
  are versioned and tolerant. An unloadable row is marked failed with an audit event, never left
  pending forever — except a row whose task kind this build does not register, which stays
  pending (a later build may load it).
- **D7** Client-facing action status visibility uses the one shared allowlist
  `VISIBLE_ACTION_STATUSES`. No new hard-coded visibility lists; internal sweeps and not-deleted
  checks are exempt.

## P — Breaking-change procedure (expand / contract)

1. **Expand**: add the reader in N. Backport it to the latest patch of all supported lines.
   Add a cap if peers or clients choose by it. Add a `COMPAT.md` entry: what, cap, reader-in
   releases, write-gate condition, removal epoch.
2. **Switch**: transport-level → per peer by cap. Token-level → once the write gate (W7) is met.
3. **Telemetry**: receiving the old format emits a deprecation audit event.
4. **Contract**: drop the old writer, then the old reader at the earliest epoch after
   deprecation once telemetry is quiet.

**Security exception.** A vulnerability may break compatibility immediately. Patch every
supported line the same day and publish an advisory. Write the reason in `COMPAT.md`.

## T — Tests (merge blockers)

- **T1** A PR touching a surface in PRD §2 gets the `compat` label and passes this checklist.
- **T2** Golden-corpus additions:
  - A new type, subtype, claim or content field adds golden-corpus tokens.
  - A new or changed response adds or updates a snapshot. Snapshot updates may only **add** keys.
  - App document schema changes add golden documents.
- **T3** Every release freezes its corpus under its version. CI checks the current build
  against the corpora of all supported releases.
- **T4** Access-matrix rows for new inbound paths, per CLAUDE.md, including refusals: unknown
  type, unlisted subtype (never supersedes), unknown `crit`, the same inside `related`.
- **T5** The refuse path and the sender's `deliveryError` are exercised end to end with the
  test-only action type.

## PR checklist (copy into the PR template)

- [ ] Touches tokens, `/inbox`/`/outbox`, `/me`, file sync, proxy tokens, REST, WS, app bus,
      CRDT document schemas, serialized state or migrations?
      If not, done.
- [ ] Only additive (W1–W2, A1–A2)? If not, is there a `COMPAT.md` entry following P?
- [ ] New must-understand field, claim or restriction flag listed in `crit`? New subtype listed in
      `subtypes`? UX acceptable when older nodes refuse it (W3)?
- [ ] Inbound limits unchanged, or raised via P (W10)?
- [ ] Remote-usable client feature detectable (A4)? New response enums decoded as open?
- [ ] Unknown values fail closed? No `deny_unknown_fields` on request or stored structs?
- [ ] New side effects go through `effects()`?
- [ ] Golden corpus / snapshots / documents updated (additions only)?
- [ ] Access-matrix rows added for new inbound behavior?
