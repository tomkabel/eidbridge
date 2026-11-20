---
project_name: eidbridge
status: planning
created: 2026-11-18
updated: 2026-11-20
---

# eidbridge project context

## Observed project state

BMAD is installed. No application source, build manifest, application CI or implementation tests were observed during the 2026-11-18 inventory. Planning artifacts are under `_bmad-output/planning-artifacts`; implementation tracking belongs under `_bmad-output/implementation-artifacts`; durable project knowledge belongs under `docs`. Never treat the presence of planning documents or another project's test results as implemented functionality.

## Product boundary

Build a self-hosted Go Smart-ID RP API v3 → OIDC bridge, device-link first with a measured notification fallback. Use config-only integrations for existing IdPs. Production integrators bring their own relying-party agreements and credentials. The project is unofficial; names describe compatibility and confer no endorsement, certification, identity assurance level or qualified trust-service status.

Zero telemetry and no persistent personal authentication state are defaults. Keep protocol/session secrets out of logs at every level. Signing keys and public trust configuration are not user-session retention. A failed public demo spike is evidence to stop and reconsider, not permission to silently implement a different product.

## Source authority

The live GitHub issue snapshot is authoritative for issue wording, state, labels, acceptance criteria and deferred gates. The competitive research supplies strategy and alternatives; conflicting conclusions must be recorded. Comparative competitor rankings do not override dependency order or release safety. Sources remain unchanged.

## Planning artifact navigation

The authoritative planning index is [planning-artifacts/README.md](planning-artifacts/README.md). Stable FR-001–FR-030 map source GitHub issue numbers; all source issues remain open. Thirty parent stories across eight epics preserve 111 original AC. All development status remains backlog; original deferred labels/gates are in roadmap and traceability. Four high-effort deferred parent stories require child decomposition before sprint readiness.

## Reconciled constraints

Use normal TLS plus rotating pins, never pin-disable as CA-disable. Persistent operator signing keys do not permit persistent identity data. Delete verified certificate/session secrets early; retain minimal one-use code delivery data only through exchange/expiry. DEBUG is never exempt from redaction. Do not assert acr high/legal assurance solely from method/certificate labels. Store spec link/version/hash metadata, not unlicensed vendor text. Configure one OIDC issuer; future wallets adapt to it.

Original source estimates total 50–51h for issues 1–18 and 42–43h for core, against the source's 40h narrative. Source dates/capacity are hypotheses. Future MID/Web eID fallback is a scope decision, not permission to bypass demand/security gates. The frozen independent coverage checker and limitations are recorded in readiness report.

Source-aligned stories are parents: implementation prerequisites mean availability of the earlier execution packet, not completion of every parent acceptance check. Sink-only logging precedes the spike; full-login logging regression and legal container/template checks close later at integration/release. Use the explicit packet sequence in epics to avoid a semantic parent-closure cycle.

## Owner override (2026-11-20)

The project owner overrode every activation, demand, deferral and stop/replan gate on 2026-11-20; see [the override record](planning-artifacts/sprint-change-proposal-2026-11-20.md). All 30 stories are in scope in packet order, then epics 4–8. Gates are now disclosure requirements: each unmet gate is listed beside its feature and a story whose original criteria pass without the gate evidence is `done-with-disclosure`, never `done`. Original acceptance criteria, decomposition of high-effort stories, privacy/trust NFRs, the single OIDC issuer and the frozen verifier are unchanged. Publication, tagging, issue edits and outreach stay owner actions. Live evidence that was not obtained is recorded as NOT RUN.
