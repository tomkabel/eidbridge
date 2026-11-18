# Implementation readiness judgment: eidbridge planning set (2026-11-18)

Gate applied: `.agents/skills/bmad-sprint-planning/references/readiness-gate.md`. Question: could a developer implement these epics without inventing decisions nothing records?
Scope read in full: product brief, PRD, architecture.md, ux-design-specification.md, epics.md (stories 1.2, 2.1-2.8, 3.1-3.6, 4.1-4.2, packet section; 5.x-8.x skimmed by heading), roadmap.md, source-reconciliation.md, addendum.md (issues 1-11 in full, rest by grep), README.md, readiness report, architecture-remediation-plan.md, spec-pins.
`tools/check-arch-trace --skip-mermaid` run once: all gates PASS. It only proves that every review finding has a row, so it cannot catch the gaps below, which fall outside the 82 findings.

## Verdict: CONCERNS

The ADR-001..010 / state machine / lifecycle / capacity / config-invariant material is specific and mostly traces to story ACs, and the packet order (LEGAL, SCAFFOLD, LOGS, SPIKE) is buildable now. The spike and scaffold can proceed. Before Epic 2 is sprint-ready, fix the contradictions and untraced decisions below via `bmad-correct-course` (cross-cutting) or `bmad-create-epics-and-stories` (AC repairs).

## Findings, by severity

### High

1. **Epics NFR inventory is stale against the PRD (epics.md:58-71 vs prd.md:289-302).** epics.md still carries the pre-remediation NFR-003, 005, 006, 007, 013, 014 text. Missing from the epics copies: code-store ceiling and per-IP/per-client quotas, `Retry-After`, monotonic clock, failed-exchange-consumes-code, sealed opaque tokens, pin-disable acknowledgement flag, `mode` required with no default, demo-keystore fingerprint check, emergency key revocation, readiness definition and SIGTERM drain. Stories cite "NFR coverage" (epics.md:88) against this older copy, so a reader of epics alone builds to the weaker NFRs. Fix: replace with the PRD text (`bmad-create-epics-and-stories`).

2. **Original AC contradicts remediation AC in Story 2.2, with no supersession note.** epics.md:316 says production without pins starts if `EIDBRIDGE_SMARTID_TLS_PINS=disabled` "logs a warning". [E17] (epics.md:323), NFR-006 (prd.md:294) and ADR-003 (architecture.md:205,222) require a second acknowledgement flag or startup fails. The story says both criteria must be satisfied. Story 2.3 handles this correctly ("Supersedes...", epics.md:362); 2.2 does not.

3. **The chooser-with-fake-method position contradicts ADR-006 in five places.** ADR-006 (architecture.md:256) and [A17] (epics.md:849) say the chooser UI and Mobile-ID activate together, and only the registry contract test uses a fake method. Still asserting the opposite:
   - epics.md:845 (Story 4.1 reconciliation: "implement chooser with a fake second method after #5").
   - roadmap.md:98 (gate for #20: "fake backend first").
   - source-reconciliation.md:32 ("implement/test chooser with fake backend then MID").
   - implementation-readiness-report-2026-11-18.md:42 ("Chooser uses a fake method before Mobile-ID").
   - ux-design-specification.md:59 ("Test chooser with fake method first").
   A developer on Story 4.1 gets two incompatible instructions.

4. **ADR-008 normative rules have no story AC or NFR.** `check-arch-trace` only covers the 82 review findings, so these slipped through. grep of epics.md for `9207`, `iss`, `prompt`, `max_age`, `no-store`, `303` returns nothing.
   - RFC 9207 `iss` in every authorization response and in discovery (architecture.md:107,317). The remediation plan promised it for Story 2.4 (plan:225-226) but it was not added.
   - Authorize-parameter table: `prompt`, `max_age`, `auth_time`, `claims`/`request` rejection, no redirect before client/redirect_uri validation (architecture.md:311-318).
   - Token and userinfo `Cache-Control: no-store`, userinfo header-only, HTTP 303 after POST (architecture.md:330-331).
   - Tombstone cap, which gives 503 at flow creation when full (architecture.md:361). The replay deny-list is "bounded" (architecture.md:305) but has no cap in the capacity model.
   - Config invariants "HTTP issuer in production fails" and "`K_sub` missing in production fails" (architecture.md:224,226): only the NFR-007 prose mentions the issuer, and no AC names either.
   - Story 2.7's [E16] covers only demo-meets-production; the production-meets-demo direction rests on the original AC alone.

### Medium

5. **Terminal-state retry is not recorded, and artifacts conflict.** UX (ux-design-specification.md:30-32) and PRD UJ-3 (prd.md:25) promise a fresh bounded retry from refused/expired/failed. ADR-002 (architecture.md:130,186,193) removes the flow entry and clears the flow cookie on every terminal state. No document says whether the user is redirected to the client with an error (which code?) or restarts from a bridge-held authorize context. The architecture records `error=access_denied` only for an unknown flow handle (architecture.md:352). Developers must invent the terminal-response contract. Related: [E10] (epics.md:504) lists refused/expired/failed and unexchanged codes but not `verified` or `cancelled`, though ADR-002 says "every terminal state".

6. **Q-05 means two different things.** PRD Q-05 (prd.md:346) is native-speaker review plus the concrete IdP matrix. Architecture Q-05 (architecture.md:26,260) is the future-method/demand gate for ADR-006. Same ID, different gates and owners.

7. **Decisions explicitly left open have no owner gate.**
   - ADR-007 "pairwise default... still needs confirmation" (architecture.md:274). It is not under Q-02 or Q-03 as defined in the PRD, and A03/A04 do not fix a default.
   - ADR-008 (architecture.md:309) leaves token lifetime, clock skew, size limits and rate thresholds as "explicit configuration decisions before FR-006/FR-007 complete". Nothing assigns them.
   - ADR-008 hands `private_key_jwt` in v1 to Q-03 (architecture.md:302), but PRD Q-03 (prd.md:346) covers only library choice and conformance plan.

8. **Configuration surface is ambiguous.** The architecture and NFR-007 require `mode` (required, no default). The addendum uses `EIDBRIDGE_SMARTID_ENV=demo|production` (addendum.md:223), lists it as a demo indicator (addendum.md:306), and also uses `EIDBRIDGE_MODE` (addendum.md:311; epics.md:536). `--demo` sets endpoints (addendum.md:228). The relationship among the three is never stated, and `docs/configuration.md` is CI-checked against the struct (Story 2.5). Note also epics.md:536 versus `mode` having no default (does `--demo` supply it?).

9. **Forward dependency in Story 2.7.** AC at epics.md:539 requires `docs/keycloak.md`. Story 2.7's prerequisite is 2.5; the Keycloak guide belongs to Story 3.5 (prereqs 2.4, 3.2) and is named `docs/idp/keycloak.md` there (epics.md:768; prd.md:159). The two paths differ, and roadmap.md:47 says `docs/keycloak.md`.

10. **Addendum contradicts the architecture despite its precedence clause (addendum.md:13).**
    - Line 635 (issue #26 doctor) makes `/readyz` include a cached upstream handshake. ADR-009 (architecture.md:350) and NFR-014 (prd.md:302) say a health probe never calls the network.
    - Line 195 `sub` formula omits the `"eidbridge-sub-v1" ‖ 0x00` domain prefix and separators from ADR-007 (architecture.md:270). ADR-007 claims "addendum.md is corrected" (architecture.md:290).
    - Addendum.md:187 "key... generated at start" conflicts with the production operator-supplied key rule (NFR-007) for the production path.
    Deferred Story 7.3 will inherit the stale text.

11. **UX state model and architecture state machine disagree.** UX diagram (ux-design-specification.md:21-34) has `App` and `Delivered`, `Failed` only from `App`, and no `cancelled`. Architecture (architecture.md:144-168) has seven states and `Pending -> failed` via poll results. UX line 36 centres verification-code comparison on the main flow, but the architecture says device-link shows none and notification mode does (architecture.md:105).

### Low

12. **Smaller inconsistencies, each verified in the text.**
    - [A09] (epics.md:450) says an abandoned flow "cancels its upstream poll"; ADR-009 (architecture.md:349) says only the local poll stops and the upstream session expires, and [E03] says no cancel is attempted. Wording should say "stops local polling".
    - Two [A10] bullets (epics.md:451-452); the second names `TestWeb2AppCallbackBinding`, which is not in the Review resolution row for A10 (architecture.md:403). The [A11] bullet duplicates the no-cookie callback rule.
    - NFR coverage (epics.md:88) maps NFR-003 only to 2.6, but its capacity ACs (A08, E04, E05) live in 2.5.
    - ADR-006 (architecture.md:258) says none of ADJ-01..18 is an initial-release promise, while source-reconciliation.md:127-135 adopts/adapts ADJ-02/03/04/07/08/09/10/13 into core.
    - README.md does not index `architecture-remediation-plan.md`, `research/architecture-review-2026-11-18.json`, `rfc9700-checklist`, `smart-id-v3-facts`, or `tools/check-arch-trace`. The readiness report (50 lines) predates and never mentions the remediation or the trace tool, although the plan (plan:232) said to replace it.
    - `architecture-remediation-plan.md` is a status-draft planning artifact with stale content (for example "abandoned flow cancels its upstream poll", plan:170) sitting beside the authoritative documents.

## What traces correctly (checked)

- Remediation ACs [A01-A17, E01-E23] in stories 1.2, 2.1-2.8, 3.1, 3.4 and 4.1 match the Review resolution table IDs, sections and test names.
- State-machine table, `endResult` map, lifecycle, capacity and config-invariant tables are internally consistent. Exception: the issuer and K_sub invariants have no AC (finding 4).
- PRD anchors referenced from architecture resolve; README file pointers exist (`project-context.md`, `sprint-status.yaml`, `docs/project-overview.md`, research files).
- Smart-ID pin 3.2.8 / OpenAPI 3.1 statement in ADR-001 matches `docs/spec-pins/spec-pins.json` and the facts note.
- Parent dependency graph is earlier-first; execution packets remove late-integration backedges.
- Orphans: no FR without a story; no story without an FR. Direction "intent to story" is complete for FR-001..030.

## Fix routing

- Findings 1, 2, 3 (epics side), 4, 9, 12 (A09/A10, coverage map): `bmad-create-epics-and-stories` for AC and inventory repair.
- Findings 3 (UX/roadmap/readiness/source-reconciliation), 10, 11: affected artifact owner skills (`bmad-ux`, `bmad-architecture`), or `bmad-correct-course` for the cross-cutting ADR-006 sweep.
- Findings 5, 6, 7, 8: `bmad-architecture` plus `bmad-prd` (new Q-gates or ADR text); finding 5 may need an ADR-011 on the terminal-response contract.
- Finding 12 (README, readiness report): regenerate with the readiness workflow.
