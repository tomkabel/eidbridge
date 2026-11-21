---
name: Upstream change
about: Track an upstream API, TLS, certificate or demo-key change
labels: upstream-change
---

## Change type
- [ ] RP API version
- [ ] TLS policy
- [ ] Server certificate renewal
- [ ] CA rotation
- [ ] Demo key rotation

## Detection evidence
- Link:
- Date:
- Hash:

## Release checklist
- [ ] Update `docs/spec-pins/spec-pins.json`
- [ ] Update `trust/<env>/`
- [ ] Update `internal/smartid`
- [ ] Add tests covering the change
- [ ] Release type: patch for pins/CA, minor for API changes
- [ ] Backport decision (one minor back for trust fixes):
- [ ] CHANGELOG "Upstream compatibility" entry
- [ ] Deviation record, if any
- [ ] Notify operators
