---
title: eidbridge planning index
status: complete-source-integration
created: 2026-11-18
updated: 2026-11-18
---

# eidbridge BMAD planning index

The competitive research and all 30 existing GitHub issues are reconciled into a single source-backed planning baseline. All issues were open on 2026-11-18; twelve were labelled deferred. Planning capture is complete; product documents remain drafts until implementation decisions and evidence are available. No implementation, release, remote issue update or public outreach is claimed.

## Local-only evidence

The competitive research data (`research/competitive-signals.csv`, `research/competitive-watch.csv`) is git-ignored and not published; entries marked "local only" refer to it. `tools/verify_bmad_artifacts.py` also reads those files and the external research root named in `source-reconciliation.md`, so it runs only on the author's machine. `tools/check-arch-trace` uses only published files.

## Continue work

Begin with the LEGAL, SCAFFOLD, LOGS and SPIKE execution packets in epics. These implement the early portions of Stories 1.1–1.4; late full-login/container checks remain parent closure obligations and do not block the spike. Use actual test evidence to advance story status. High-effort deferred parent stories require child decomposition before sprint scheduling. Do not broaden to EUDI, signing, an SDK or a native SPI because those ideas were captured.

| Start here | Purpose |
|---|---|
| [Product brief](product-brief-eidbridge-2026-11-18.md) | Product wedge, evidence strength, counter-case and first decisions |
| [PRD](prd.md) | 30 stable functional requirements, 14 NFRs, scope, assumptions and open implementation questions |
| [Architecture](architecture.md) | Decision index, threat model, ten decision records (trust, identity, tokens, lifecycle, capacity), state machine and review traceability |
| [UX requirements](ux-design-specification.md) | Device handoff/error/accessibility/localization behavior; visual design remains future work |
| [Epics and stories](epics.md) | Eight epics, 30 source-aligned parent stories and all 111 original acceptance criteria |
| [Roadmap](roadmap.md) | Release increments, source milestones, capacity gap and deferred gates |
| [Source reconciliation](source-reconciliation.md) | Conflicts and every research suggestion's disposition |
| [Independent review](research/review-source-and-editorial-2026-11-18.md) | Five source/structure findings and recorded corrections |
| [RV resolutions](research/planning-review-rv-resolutions-2026-11-18.md) | All 32 planning review items mapped to changes and acceptance evidence |
| [Readiness report](implementation-readiness-report-2026-11-18.md) | Structural validation and unresolved implementation/release gates |
| [Technical source addendum](addendum.md) | Original proposed solutions, API sketches, exclusions and full notes |
| [GitHub snapshot](research/github-issues-2026-11-18.json) | Complete dated live issue bodies/state/labels |
| [Source manifest](research/source-manifest.json) | Input hashes and classification, including supporting evidence |
| [Traceability register](research/traceability.json) | Machine-readable issue/requirement/story/dependency and research maps |
| Canonical signals (`research/competitive-signals.csv`, local only) | 54 source signals with dates/caveats, no shard double count |
| Competitive watch (`research/competitive-watch.csv`, local only) | Ten original forecasts unresolved until their evidence/deadline permits |
| [Validation baseline](research/validation-baseline-2026-11-18.json) | Frozen check failed before authoring, 232 missing-coverage failures |
| [Validation result](research/validation-result-2026-11-18.json) | Final frozen coverage-proxy result |
| [Project context](../project-context.md) | Current state and reusable product boundaries |
| [Backlog status](../implementation-artifacts/sprint-status.yaml) | All epics/stories backlog; deferred gates remain explicit |
| [Architecture remediation plan](architecture-remediation-plan.md) | Plan for closing the 82 review findings, with phases and pass criteria |
| [Architecture review findings](research/architecture-review-2026-11-18.json) | All 82 findings with IDs (A, E, S, P); traced in architecture.md Review resolution |
| [Spec pins](../../docs/spec-pins/spec-pins.json), [Smart-ID v3 facts](research/smart-id-v3-facts-2026-11-18.md), [RFC 9700 checklist](research/rfc9700-checklist-2026-11-18.md) | Pinned specification metadata and paraphrased facts the architecture relies on |
| [Project knowledge](../../docs/project-overview.md) | Entry point discoverable through configured project_knowledge |


## Verify planning artifacts

Run the frozen source-preservation checker from the project root:

~~~sh
python tools/verify_bmad_artifacts.py
tools/check-arch-trace
~~~

It checks source hashes, mappings, original AC, document links and dependency ordering. It does not prove semantic completeness, legal applicability, security or functioning authentication. The protected verifier was authored independently before candidate artifacts, and its expectations were not changed to fit the result. The checker is a dated snapshot: re-baseline intentionally for new source/issue changes, never silently weaken it.
