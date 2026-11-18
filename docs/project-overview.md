---
project: eidbridge
status: planning
updated: 2026-11-18
---

# eidbridge project overview

Self-hosted Go Smart-ID RP API v3 to OIDC bridge; unofficial, operator-controlled, no default persistent personal authentication state or telemetry. No application implementation or test pass is claimed as of 2026-11-18.

The authoritative [planning index](../_bmad-output/planning-artifacts/README.md) links the product brief, PRD, architecture, UX, epics, roadmap, issue/source reconciliation and evidence. [Project context](../_bmad-output/project-context.md) describes verified current state. [Backlog tracking](../_bmad-output/implementation-artifacts/sprint-status.yaml) remains entirely backlog. Research root is /home/notroot/research/competetive (original spelling).

Thirty open GitHub issues, including twelve deferred, map to thirty functional requirements and eight epics. Every original acceptance criterion and note is retained. No source research, GitHub state or framework core was changed. Deferred EUDI, Web eID, signing, SDK, plugin, legacy and operator tooling are options with explicit gates, not initial release commitments.

Implementation docs such as docs/security.md, docs/data-flow.md, docs/legal.md and docs/idp guides are future acceptance deliverables, not silently generated claims that implementation exists. Start with the notices/scaffold/safe-logging/spike sequence in the roadmap. Verify source integration using python tools/verify_bmad_artifacts.py; passing it proves structural preservation only.
