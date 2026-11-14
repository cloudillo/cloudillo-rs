## Summary

<!-- What changes and why. -->

## Compatibility checklist

Rules: `docs/compat-rules.md`. Registry: `COMPAT.md`.

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
