---
title: eidbridge roadmap and decision gates
status: draft
created: 2026-11-18
updated: 2026-11-18
inputDocuments:
  - research/github-issues-2026-11-18.json
  - research/source-manifest.json
---

# Roadmap and decision gates

## Delivery decision

Retain the narrow Smart-ID RP v3→OIDC wedge and all deferred alternatives. Implementation sequence follows the execution packets and separate parent-closure checks in epics, dependencies and release safety, not the comparative incumbent-exposure ranking. No feature or issue is implemented by this documentation pass. All original 15 milestones, nine opportunities, fourteen capabilities and ten forecasts have explicit homes.

## Capacity and dates

The original plan assumes 10h/week and four weeks/40h. Summing the actual Notes estimates gives **50–51h for issues 1–18** and **42–43h for core issues 1–14,16,17**. At 10h/week these imply 5.0–5.1 and 4.2–4.3 weeks respectively before unestimated translation review, live setup, integration churn, external review or support. These are unvalidated source estimates, not forecasts of actual delivery; no arbitrary contingency has been added.

Source proposal targets: core 2026-12-21; integration kits 2027-01-11. Reference date is 2026-11-18; neither is a confirmed commitment. The 2026-11-16 forecast window resolves on **2027-02-14**, independent of actual launch. The source sometimes calls that day 90 while using four-week launch dates; actual adoption L+90 begins at actual release. If work begins on 2026-11-18, four calendar weeks end 2026-12-16, which demonstrates the source dates were not one coherent sprint calendar. Reconfirm calendar/capacity after the spike.

## Dependency-ordered increments

| Increment | Work | Exit evidence | Stop/replan condition |
|---|---|---|---|
| R0 feasibility | Epic 1, #12/#1/#9/#2 | Clean-room/CI/logging foundation; six-hour capped verified demo spike, sanitized fixtures and ADR | Contract/payment blocks public demo or no feasible verified path; record outcome, reconsider product |
| R1 authentication preview | Epic 2, #3/#8/#5/#6/#7/#10/#11/#4 | Verified device-link and optional notification, exact OIDC negative tests, memory/egress/log isolation, environment separation | No verified OIDC round-trip inside source week-2 ten-hour budget → stop feature expansion and re-estimate |
| R2 hardened demo release | Epic 3 #13/#14/#16/#17 plus completed R0/R1 | Data-flow/security/ops docs, reviewed five locales, release artifact evidence and clean-clone demo under five minutes | Stranger test fails → source week 4 becomes polish, no launch or extra packages |
| R3 adoption kits | Epic 3 #15/#18 | Config-only four-IdP matrix and Django/FastAPI e2e evidence, dated versions and production demo rejection | Do not add native plugins or second protocol codebase to compensate for unfinished standard integration |
| R4+ future options | Epics 4–8 | Original gates plus reviewed per-option implementation plan | No automatic activation from rank, news, registry gap or this capture task |

R1 is a preview label until all core source AC and R2 release gates pass. Security/privacy/agreements are requirements throughout, never a final cosmetic pass. Notifications are opt-in; the core backlog retains #4 even if an earlier experiment omits it explicitly.

## Gates for every deferred GitHub issue

| Issue / story | Original gate and dependency | Release evidence beyond source AC |
|---|---|---|
| #20 / 4.1 | Demand for a second method; chooser and Mobile-ID activate together; until then only the registry contract test with a fake method | Client restriction/assurance, keyboard behavior, amr and single-method bypass; cookie privacy update |
| #19 / 4.2 | Stable Smart-ID and deployments asking for MID; chooser/interface | Signed/negative fixtures, phone field inventory, rate limits/demo-key rotation |
| #21 / 5.1 | Concrete ID-card deployment, stable core, test hardware and external security review | Split 80–100h validation/status/browser work, fuzz/origin/replay/revocation and real test-card evidence |
| #22 / 6.1 | Testable national/reference wallet, stable profile and RP demand; compare native IdP route | Split 60+h work, signed verifier identity/registration/claim ceilings, holder/trust/status negatives and interop |
| #23 / 6.2 | Verified wallet method and pinned profiles | Separate >60h harness scope, positive and ≥10 negatives, versioned JUnit/spec links |
| #24 / 7.1 | At least three concrete unmet config-only integration requests | Java maintenance budget; two latest Keycloak-major e2e compatibility |
| #25 / 7.2 | At least two direct-library requests | Second-language maintenance, shared Go/Python negatives, neutral package naming |
| #26 / 7.3 | First outage existing diagnostics fail to explain | Local JSON schema, expiry/pin/unreachable tests, configured egress only |
| #27 / 7.4 | External offline-test demand | Standalone safe mock distinct from required internal fixture service; no real CA/identity data |
| #29 / 7.5 | Concrete deployment unable to use v3 | v2 negative suite and migration; no v1 scope |
| #30 / 7.6 | WordPress users request login; standalone mock available per source | Existing OIDC plugin guide first, only build plugin for proven remaining gap |
| #28 / 8.1 | Stable v1 authentication plus deployment signing need | Split 40+h API/security/relay/container/review; authenticated API and independent container validator; no QES claim |

Adjacent optional audit, multi-RP tenant mode, PKCS11, registrar export, age predicate/WooCommerce and external wallet-authorized remote signing have additional design gates in [source reconciliation](source-reconciliation.md#deferred-adjacent-wallet-candidates). They are retained research options and cross-project handoffs, not new committed issues. Production Helm/systemd, more framework SDKs, public plugin ABI and a shared state store also stay demand-gated.

## Original 15 milestones, reconciled

| Source milestone | Original deliverable | Disposition and home |
|---|---|---|
| ms:skid:SK-W1-M1 | cmd/sidspike device-link spike | adapt: FR-002/Story 1.4; source estimate/date is a hypothesis. |
| ms:skid:SK-W1-M2 | repo scaffold + CI | adapt: FR-001/Story 1.2; source estimate/date is a hypothesis. |
| ms:skid:SK-W1-M3 | docs harvest / spec pins | adapt: FR-001/Story 1.2; source estimate/date is a hypothesis. |
| ms:skid:SK-W2-M1 | internal/smartid RP v3 client | adapt: FR-003/Story 2.1; source estimate/date is a hypothesis. |
| ms:skid:SK-W2-M2 | internal/oidc provider surface | adapt: FR-006/Story 2.4; source estimate/date is a hypothesis. |
| ms:skid:SK-W2-M3 | cmd/eidbridge wiring | adapt: FR-007/Story 2.5; source estimate/date is a hypothesis. |
| ms:skid:SK-W2-M4 | CI build matrix | adapt: FR-001/Story 1.2; source estimate/date is a hypothesis. |
| ms:skid:SK-W3-M1 | Dockerfile + compose | adapt: FR-014/Story 3.2; source estimate/date is a hypothesis. |
| ms:skid:SK-W3-M2 | README + docs/keycloak.md | adapt: FR-015/Story 3.5; source estimate/date is a hypothesis. |
| ms:skid:SK-W3-M3 | release automation | adapt: FR-001/Story 1.2; source estimate/date is a hypothesis. |
| ms:skid:SK-W3-M4 | hardening pass | adapt: FR-009/Story 1.3; source estimate/date is a hypothesis. |
| ms:skid:SK-W4-M1 | smart-id-rp PyPI package | defer: FR-025/Story 7.2; source estimate/date is a hypothesis. |
| ms:skid:SK-W4-M2 | django/fastapi examples | adapt: FR-018/Story 3.6; source estimate/date is a hypothesis. |
| ms:skid:SK-W4-M3 | launch artefacts | plan-only: Prepare launch checklist only; public posts/publication are future human actions. |
| ms:skid:SK-W4-M4 | maintenance scaffolding | adapt: FR-017/Story 3.4; source estimate/date is a hypothesis. |

The milestone IDs are synthetic inventory locators from rankings/inventory.csv; not every original plan heading contains that anchor. W3 Keycloak documentation maps to #15 but may be prepared alongside demo hardening; full multi-IdP matrix is R3. W1 docs harvest becomes link/version metadata, not copied unlicensed specification text. W4 PyPI package is deferred by #25 and neutral naming policy, despite the older distribution recommendation.

## All nine source opportunities

| ID | Original research status/priority | Current disposition | Reason |
|---|---|---|---|
| OPP-04 | ranked / 0.031134 | adopt | Initial Smart-ID/OIDC wedge, FR-001–014. |
| OPP-09 | ranked / 0.028560 | adopt | Config-only guides/fixtures, FR-015/018 after core. |
| OPP-01 | excluded / 0.019895 | defer | Generic OIDC first; native SPI only after three unmet user requests, #24. |
| OPP-06 | excluded / 0.010569 | defer | No hosted monitor; local doctor only after diagnostic-gap outage, #26. |
| OPP-02 | excluded / 0.006227 | defer | Supply gap is not demand; examples now, direct Python client after two asks, #25. |
| OPP-03 | excluded / 0.004812 | defer | Umbrella multi-method product depends on core/backends, not an additional independent 60-hour task. |
| OPP-08 | excluded / 0.003850 | defer | 80–100-hour Web eID requires demand and external review, #21. |
| OPP-05 | excluded / 0.003306 | defer | EUDI harness after wallet method and profile pinning, #23. |
| OPP-07 | excluded / 0.002418 | defer | Internal fixtures now; standalone toolkit after external demand, #27. |

The original risk-discounted score is demand × feasibility × (1−incumbent probability) / weeks-until-announcement. Inputs are study judgments, not measured willingness-to-pay. Do not recompute dates from today and silently reuse the old priority. The ranked lead dates are historical forecast inputs, not current facts.

## All fourteen comparative capabilities

| ID | Comparative label | Disposition | Requirement/story |
|---|---|---|---|
| S1 | Self-hosted Smart-ID RP v3 → OIDC provider bridge | adopt | Complete umbrella scope: FR-001, FR-002, FR-003, FR-004, FR-005, FR-006, FR-007, FR-008, FR-009, FR-010, FR-011, FR-012, FR-013, FR-014, FR-016, FR-017. Stories: 1.2, 1.4, 2.1, 2.8, 2.3, 2.4, 2.5, 2.2, 1.3, 2.6, 2.7, 1.1, 3.1, 3.2, 3.3, 3.4. Shared requirements are not additive effort; original primary link was an anchor, not complete scope. |
| S2 | Mobile-ID method beside Smart-ID in the same bridge | defer | Complete umbrella scope: FR-019. Stories: 4.2. Shared requirements are not additive effort; original primary link was an anchor, not complete scope. |
| S3 | Web eID / ID-card token validation in the bridge | defer | Complete umbrella scope: FR-021. Stories: 5.1. Shared requirements are not additive effort; original primary link was an anchor, not complete scope. |
| S4 | Multi-method broker: one OIDC issuer over Smart-ID, Mobile-ID and Web eID | defer | Complete umbrella scope: FR-001, FR-002, FR-003, FR-004, FR-005, FR-006, FR-007, FR-008, FR-009, FR-010, FR-011, FR-012, FR-013, FR-014, FR-016, FR-017, FR-019, FR-020, FR-021. Stories: 1.2, 1.4, 2.1, 2.8, 2.3, 2.4, 2.5, 2.2, 1.3, 2.6, 2.7, 1.1, 3.1, 3.2, 3.3, 3.4, 4.2, 4.1, 5.1. Shared requirements are not additive effort; original primary link was an anchor, not complete scope. |
| S5 | EUDI Wallet presentation method (OpenID4VP) in the bridge | defer | Complete umbrella scope: FR-022. Stories: 6.1. Shared requirements are not additive effort; original primary link was an anchor, not complete scope. |
| S6 | Keycloak SPI plugin for Smart-ID | defer | Complete umbrella scope: FR-024. Stories: 7.1. Shared requirements are not additive effort; original primary link was an anchor, not complete scope. |
| S7 | Config-only IdP integration guides with CI-executed examples | adopt | Complete umbrella scope: FR-015, FR-018. Stories: 3.5, 3.6. Shared requirements are not additive effort; original primary link was an anchor, not complete scope. |
| S8 | Official Python RP client | defer | Complete umbrella scope: FR-025. Stories: 7.2. Shared requirements are not additive effort; original primary link was an anchor, not complete scope. |
| S9 | RP API health/monitoring check (doctor) | defer | Complete umbrella scope: FR-026. Stories: 7.3. Shared requirements are not additive effort; original primary link was an anchor, not complete scope. |
| S10 | Offline demo toolkit (mock RP API + test identities) | defer | Complete umbrella scope: FR-027. Stories: 7.4. Shared requirements are not additive effort; original primary link was an anchor, not complete scope. |
| S11 | EUDI conformance harness | defer | Complete umbrella scope: FR-023. Stories: 6.2. Shared requirements are not additive effort; original primary link was an anchor, not complete scope. |
| S12 | Signing sessions (authentication plus signing) | defer | Complete umbrella scope: FR-028. Stories: 8.1. Shared requirements are not additive effort; original primary link was an anchor, not complete scope. |
| S13 | Legacy RP API v1/v2 compatibility | defer | Complete umbrella scope: FR-029. Stories: 7.5. Shared requirements are not additive effort; original primary link was an anchor, not complete scope. |
| S14 | WordPress plugin or guide for Smart-ID | defer | Complete umbrella scope: FR-030. Stories: 7.6. Shared requirements are not additive effort; original primary link was an anchor, not complete scope. |

S4 multi-method is an umbrella built from the core, chooser and additional methods. Its 60h estimate must not be added independently to S1's 42.5h and Web eID's 80–100h as if disjoint. Ranking S4 first does not make it precede core. S8's source word “Official” does not authorize affiliation. S13 supports v2 only, not v1, and its success means valid v2 accepted, not blanket legacy rejection. S12 is deferred digest relay, not proof that the project must become a QTSP.

## Original launch and distribution plan

One repo, README as landing page, one runnable demo; no separate marketing site. Use distinct clocks: implementation day I0 begins actual implementation; launch day L occurs only when release gates pass; adoption review is L+90. The original project day ~30 was its proposed launch, not 30 days after release. Prepare Show HN and r/selfhosted material for L; after feedback, useful ARF/authentik/Keycloak reply drafts can follow around L+5–15 and community/registry/catalogue material around L+20–60. These preserve source spacing as proposed timing, not confirmed commitments. Potential catalogue targets: authentik integrations, awesome-keycloak/selfhosted and Zitadel community integrations. Estonian developer/e-residency communities are source channel hypotheses; no Slack/email/issue outreach was authorized or sent in this task.

Prepare drafts only when an actual artifact can be linked. Public comments/posts/catalogue PRs and release/PyPI/GHCR publication require their own future execution context. No issue spam, no repeated cross-post text, no vendor logos or endorsement claims. Existing Node client gets a link, not a new competitor SDK. Optional Estonian README keeps English authoritative. Pricing comparisons need dates, total operator fees and current verification before publication; never claim self-hosting removes scheme transaction fees/minimums.

## Original market indicators and reconciliation

| Public indicator at actual L+90 | Source success / source failure | Handling |
|---|---|---|
| GitHub stars | ≥100 / <20 | Supporting discovery measure, not product proof |
| PyPI monthly downloads | ≥500 / <100 | N/A while #25 deferred; do not build package to satisfy metric |
| GHCR pulls | ≥1,000 / <200 | Record unavailable if public pull count cannot be measured reliably |
| Independent external adopters | ≥3 / 0 | Deduplicate external issue/PR/discussion reports and distinguish interest from deployment |
| Catalogue/list merges | ≥1 / 0 | Evidence is actual merged listing, not submitted PR |

The distribution source defines success as 4/5 and failure as stars AND adopters below floor; plan_30d also includes PyPI in an example failure floor. Preserve that conflict. Proposed review rule: assess core actual adopter evidence and available counters with N/A visible, then project owner decides maintenance-only/continue. This is a proposed reconciliation, not an automatic archive rule or invented replacement success threshold. Do not publish a fabricated 4/5 score with a deferred package or inaccessible registry count.

## Competitive and technical watch

Use competitive watch (`research/competitive-watch.csv`, local only): F01–F10 original forecast probabilities, evidence alternatives and resolution rules remain unchanged with blank outcome/resolved_at/Brier columns. Resolution deadline is 2027-02-14; next proposed manual review is 2026-11-25. F01 self-serve/free broker tier challenges the core thesis; F09/F10 native connectors require re-evaluation. F02 changes SDK-gap claims; F04/F05/F06/F08 affect release/pricing/method context; F03/F07 are adjacent distribution/wallet context. No forecast outcome is asserted.

A manual weekly process can compare dated API changelog/spec metadata, TLS/pins/CA changes, demo-key rotations and incumbent public artifacts. Retain evidence URL/hash/date, mark machine inference unreviewed, deduplicate demand and make owner decisions explicit. Offline design only: no background monitoring loop deployed. Separate application compatibility nightly workflow is planned under #17, not active here. The adjacent wallet project's 2026-12-15/16 watch dates remain its own future checkpoints, not new eidbridge deadlines.
