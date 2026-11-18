---
title: eidbridge source reconciliation
status: complete-source-integration
created: 2026-11-18
updated: 2026-11-18
---

# Source reconciliation

## Coverage and authority

Every live eidbridge issue and every project-relevant source proposal has a disposition. The machine-readable [traceability register](research/traceability.json) holds exact issue criteria/notes/body hashes and mappings; the [manifest](research/source-manifest.json) hashes all accessible input files. The 30 issue specifications, 9 opportunities, 14 comparative capabilities, 15 plan milestones, 54 canonical signals and 10 forecasts are reconciled separately to avoid counting the same idea repeatedly.

Source authority: user instruction → live GitHub wording/state/labels retrieved on 2026-11-18 → canonical research tables and finalized recommendations frozen 2026-11-16 → drafts/shards. Architecture resolutions are explicit proposed planning decisions, not historical source facts. No issues/comments/labels/milestones were changed remotely. No claim is made that all supporting raw payloads were manually re-read or every original research assertion independently revalidated. They are preserved by hashes for audit.

## Conflicts and resolutions

| Conflict | Source positions | Planning treatment |
|---|---|---|
| Python week-4 package | plan/distribution say ship smart-id-rp; #25 says defer until two asks, neutral eidbridge-rp name | Preserve feature/deferred label and two-request gate; OIDC examples #18 stay active. Source branding policy excludes scheme-name package. |
| Multi-method ranking vs product wedge | comparative S4 first at 60h; source plan says one method and OPP-03 infeasible | S4 is future umbrella; core precedes chooser/backends. Do not double-count overlapping S1/S4/S3 hours or use incumbent worry as user priority. |
| 40h/four-week narrative | Notes total 50–51h for #1–18, core 42–43h | Preserve original estimates but expose gap; dates/capacity reconfirmed after spike, no security cuts hidden. |
| Fallback scope explosion | failed public Smart-ID → MID → fixtures+Web eID | Record outcomes; notification is same-product alternative; other methods trigger explicit scope/security/capacity reconsideration. No automatic 80–100h fallback. |
| Legal impossibility of signing | ranking says own QTSP/QSCD required; #28 is digest relay, adjacent #18 external QTSP orchestration | Treat legal blanket claim as unsupported/overbroad. Retain demand/legal/security deferral and no qualified-status claim. |
| Legacy behavior | ranking S13 says v1/v2 and rejects fixture; #29 explicitly accepts v2, excludes v1 | Issue-specific v2 positive/negative AC governs. No published v2 sunset verified from source. |
| Four-language title vs five in body | #16 title omits Russian; body requires en/et/lv/lt/ru | Preserve all five catalogs; native review remains required. |
| Zero retention vs code exchange | #10 delete on completion; #13 until exchange; /userinfo needs valid token | Define phase-specific minimal data/TTL and destroy cert/session early; code/exchange token lifecycle explicitly resolved before implementation. No claim bridge can delete data already delivered to client. |
| Demo key volume vs no persistence | #14 key volume; #10 zero data retention | Operator signing key persists, identity/flow data does not. Production must not regenerate missing key silently. |
| DEBUG warning vs always-on privacy | source warning suggests DEBUG PII; #9 no raw logs | Warning is not permission: redact/exclude raw identifiers/secrets at every level. |
| Spec harvest vs unlicensed docs | plan suggests pinned copies; #12 says no vendor doc text | Store URL/version/hash/licence metadata only; no unlicensed prose or LGPL demo translation. |
| Pin fail-closed vs escape hatch | #8 permits explicit disabled pin | Preserve deliberate escape, normal CA/hostname checks stay on; warn and disclose hardened-mode deviation. |
| Chooser/MID loop | MID depends on chooser, chooser deferred until second method | Gate on actual second-method demand; until then only the registry contract test with a fake method exists, and the chooser UI and MID activate together (architecture ADR-006), so no dependency cycle. |
| Internal fixture vs standalone mock | e2e needs fixture; #27 deferred external toolkit | Required internal signed-fixture upstream is part of core test work; standalone CLI/control API/image deferred. |
| Signing/assurance semantics | source LoA sketch and QUALIFIED certificate level | No automatic acr=high/eIDAS/QES mapping. Resolve protocol/agreement and status responsibilities first; demo always acr=demo. |
| Competitive gate drops safeguards | ranking excludes releases/privacy/conformance for no priced surface | Applicable safety/release requirements remain release gates regardless of commercial score. |
| Wallet overlaps | eidbridge #22, adjacent OIDC bridge #13 and CMS #17 share concept | One eidbridge issuer and future method adapter; adjacent verifier may supply reviewed dependency, not another default issuer. CMS age checkout differs from WordPress login. |
| Audit evidence vs zero persistence | adjacent metadata audit/checklist may imply retention | Default off; separate privacy/legal ADR, minimal metadata and limits, hash-chain truncation limitation; no imported default database. |
| Dates and D90 | 30-day plan/December target/January kit target and fixed February review | 2026-12-21 and 2027-01-11 are original targets, not confirmed; 2027-02-14 forecast resolution fixed; adoption D+90 from actual launch. |
| Uptake rule | source 4/5 success and stars+adopters failure; other prose includes PyPI | Preserve original thresholds, show N/A when client deferred/counter unavailable; manual owner review, no invented automatic 4/5 score. |
| Forecast draft numbering/formula | analysis draft old IDs/probability multiplication; final tables corrected | Canonical forecasts F01–F10 and (1−p) in proposal/opportunities govern; outcomes and Brier stay empty. |
| Existing implementation distance | rankings say empty remote/no files; current BMAD installed | State no application implementation observed; do not say no files exist or import other projects' test passes. |

## Scope exclusions and cross-project handoffs

All glazer/fingerprintproxy/ManyFaces suggestions remain in their own projects: HTTP proxy repair, evidence capture/refusal records, RFC3161 timestamps, verification CLI, redaction/retention/export, WARC, MCP tools/safety/source offer, capture profiles/screenshots/RBI, Homebrew delivery and OSINT/STIX-MISP enrichments. They do not belong in identity-bridge epics. Individual issue exclusions are recorded below.

The adjacent eudi-wallet-poc research contributes current practices for scope/conformance/deviation disclosure, data-flow/operator guides, release provenance and incident response. Its wallet-specific signed requests, registration/export, PID parsing, trust freshness, tenants, age predicates, audit, HSM and remote signing remain gated candidates in [the section below](#deferred-adjacent-wallet-candidates). The source's proposed buyer interviews, 40h wallet plan, proxy economics, 2026-12-15/16 checkpoints and two-of-three rejection rule are retained context for that project, not imported eidbridge promises.

## Deferred adjacent wallet candidates

These extracted design candidates have explicit source homes and are not initial-release promises. ADJ IDs refer to the disposition table later in this document.

| Candidate | Required behavior/evidence before activation | Dependencies and ownership |
|---|---|---|
| ADJ-01 signed verifier requests | Request-object typ/signature, access cert x5c, computed x509_hash, cert/key and SAN/response-host consistency; unsigned testing only explicit opt-in; strict-wallet negative/interop tests | FR-022; profile/security maintainer; source is eudi-wallet-poc proposal |
| ADJ-06 registration/export | Per-RP versioned registration/intended-use/request ceiling, deterministic registrar export and runtime-ceiling comparison; unverified national formats labelled; no live submission | FR-022; operator/legal applicability review |
| ADJ-14 PID formats | SD-JWT disclosures/KB-JWT and mdoc plain presentation verified for issuer, holder, status, audience, nonce and transcript; memory-only values and fail-closed negatives | FR-022; decide reuse vs cross-project adapter explicitly, no code copied implicitly |
| ADJ-15 trust refresh | Profile-appropriate signed LOTL/TL/LoTE where applicable, service/status filters, atomic signed update, freshness/rollback tests; separate static/imported trust | FR-022; LOTL is not assumed universal wallet trust |
| ADJ-12 multi-RP | Separate RP identity/certs/keys/registered ceilings, authenticated init/result, cross-tenant negative tests/rate limits; single-tenant default | Concrete multi-RP need and FR-022, no billing/onboarding UI |
| ADJ-11 predicate guide | Minimal age proof, same-device/QR, bounded polling and server-only results; not-proven is unknown, not underage; no stable identity inferred | Compatible attestation and demand; stable OIDC account semantics require separate decision |
| ADJ-13 OIDC adapter | One existing issuer, code/PKCE, nonce binding, scope-to-minimal-claims and key rotation; privacy-preserving subject policy, no refresh/PID release without verified support | FR-006/022; avoid duplicate server |
| ADJ-16 PKCS11 | Optional file/non-exportable key backend, SoftHSM and rotation tests; default static build stays free of CGO dependency | Concrete deployment requirement; key custodian/operator owns hardware |
| ADJ-05 metadata audit | Off by default, explicit field allow-list, no tokens/attributes/nonces/keys, configured lifetime/export/access; treat even pseudonymous timestamps/client/decision identifiers as linkable | Separate privacy ADR; hash chain detects edits, cannot prove truncation without external anchor |
| ADJ-18 external remote signing | Bind wallet-approved transaction hash to external CSC v2/QTSP signHash, refuse mismatch; qualified provider retains certificate/QSCD responsibility | Compatible sandbox, demand, legal/security review; separate from FR-028 digest relay |

ADJ-17 WooCommerce age checkout is a cross-project use case, not FR-030 WordPress login and not an eidbridge feature commitment. Nextcloud/Drupal/n8n also remain unrequested adjacent options. Qualified issuance, seals, wallet certification, remote QSCD custody, credential brokerage and hosting are outside this product. No claim is made that ordinary digest relay is categorically illegal without this project's own QTSP status; source rankings overstate that point. Signing remains deferred on scope, security, demand and legal-review grounds.

## Source limitations carried forward

Four artifacts/three asks do not establish market demand; a hostname is not a shipped wallet product. LV/LT procurement registers were inaccessible, Reddit blocked, EWC membership unverified, some scheme requirements PDF bodies unread and several pricing/licensing/patent interpretations unverified. Source package inventory and incumbent versions were observed on 2026-11-16. No fresh standards/legal opinion/conformance or app run was performed. Do not claim “ready” or “compliant” from this dossier alone. Signal summaries and shards are deduplicated against the 54-row canonical signals.csv; do not count 126. Annual incumbent financial exposure is unknown.

## Issue-to-requirement and story map

| Issue | Requirement | Story | State | Prerequisites |
|---|---|---|---|---|
| #1 | FR-001 | 1.2 | backlog | none |
| #2 | FR-002 | 1.4 | backlog | 1.2, 1.3, 1.1 |
| #3 | FR-003 | 2.1 | backlog | 1.4 |
| #4 | FR-004 | 2.8 | backlog | 2.1, 1.3, 2.5 |
| #5 | FR-005 | 2.3 | backlog | 2.1 |
| #6 | FR-006 | 2.4 | backlog | 2.3 |
| #7 | FR-007 | 2.5 | backlog | 2.4, 2.1, 2.2 |
| #8 | FR-008 | 2.2 | backlog | 2.1 |
| #9 | FR-009 | 1.3 | backlog | 1.2 |
| #10 | FR-010 | 2.6 | backlog | 2.5 |
| #11 | FR-011 | 2.7 | backlog | 2.5 |
| #12 | FR-012 | 1.1 | backlog | none |
| #13 | FR-013 | 3.1 | backlog | 2.4, 1.3, 2.6 |
| #14 | FR-014 | 3.2 | backlog | 2.5, 2.7, 1.2, 2.6 |
| #15 | FR-015 | 3.5 | backlog | 2.4, 3.2 |
| #16 | FR-016 | 3.3 | backlog | 2.5 |
| #17 | FR-017 | 3.4 | backlog | 2.2, 1.2 |
| #18 | FR-018 | 3.6 | backlog | 3.2 |
| #19 | FR-019 | 4.2 | deferred | 2.3, 4.1 |
| #20 | FR-020 | 4.1 | deferred | 2.3, 2.5 |
| #21 | FR-021 | 5.1 | deferred | 4.1 |
| #22 | FR-022 | 6.1 | deferred | 4.1 |
| #23 | FR-023 | 6.2 | deferred | 6.1 |
| #24 | FR-024 | 7.1 | deferred | 3.5 |
| #25 | FR-025 | 7.2 | deferred | 2.1 |
| #26 | FR-026 | 7.3 | deferred | 2.2 |
| #27 | FR-027 | 7.4 | deferred | 2.1 |
| #28 | FR-028 | 8.1 | deferred | 2.1 |
| #29 | FR-029 | 7.5 | deferred | 2.3 |
| #30 | FR-030 | 7.6 | deferred | 7.4 |

## Research recommendation dispositions

Each locator identifies the original section, issue, or checklist row; source paths are relative to /home/notroot/research/competetive. Exact hashes are in the manifest.

| ID | Source and locator | Disposition | Artifact and rationale |
|---|---|---|---|
| SK-proposal | skidsolutions.eu/proposal.md — Executive recommendation; Opportunity ranking; Thesis attack; Evidence gaps | adopt | [product-brief-eidbridge-2026-11-18.md](product-brief-eidbridge-2026-11-18.md): Retain OIDC wedge/counter-case; forecasts and prices are dated, not outcomes. |
| SK-plan_30d | skidsolutions.eu/plan_30d.md — Weeks 1–4; fallback ladder; Do NOT build | adapt | [roadmap.md](roadmap.md): Preserve 15 milestones, budgets/tests and exclusions; reconcile dates, effort and product pivots. |
| SK-compliance | skidsolutions.eu/compliance.md — Sections 1–5 | adapt | [architecture.md](architecture.md): Adopt privacy, agreements, clean-room and claims constraints; legal/PDF interpretations remain unverified. |
| SK-distribution | skidsolutions.eu/distribution.md — Exact hooks; Ecosystems; Launch mechanics; 90-day measurement; What NOT to do | adapt | [roadmap.md](roadmap.md): Retain launch channels/metrics; no public comments/posts/catalogue PRs/publication executed. |
| SK-demand | skidsolutions.eu/demand.md — Items found; Zero-result searches; Reading | adopt | [product-brief-eidbridge-2026-11-18.md](product-brief-eidbridge-2026-11-18.md): Four artifacts are three asks, not four customers; registry supply gap is not demand. |
| SK-procurement | skidsolutions.eu/procurement.md — Current awards; Baseline | context-only | [product-brief-eidbridge-2026-11-18.md](product-brief-eidbridge-2026-11-18.md): State-service awards explain incumbent context, not available pipeline. |
| SK-oss_inventory | skidsolutions.eu/oss_inventory.md — Connector table | adapt | [architecture.md](architecture.md): Permissive reuse with notices; link maintained Node option; evaluate Go candidates before implementation. |
| SK-analysis_phase3 | skidsolutions.eu/analysis_phase3.md — Parent correction; Short seller; Thesis attack | superseded-in-part | [source-reconciliation.md](source-reconciliation.md): Canonical forecast IDs and (1-p) formula in proposal/forecasts take precedence; retain counter-case. |
| SK-artefacts_b | skidsolutions.eu/artefacts_b.md — Repo/release/package/host/version inventory | context-only | [source-reconciliation.md](source-reconciliation.md): Dated inventory observations, not current library advice or product availability. |
| SK-notes_a | skidsolutions.eu/notes_a.md — Failures/gaps; announced vs rumour | retain-limitations | [source-reconciliation.md](source-reconciliation.md): Missing pages and forecasts cannot establish availability. |
| SK-notes_b | skidsolutions.eu/notes_b.md — Failures; Coverage gaps | retain-limitations | [source-reconciliation.md](source-reconciliation.md): No verified v1/v2 EOL; archive tag is not sunset. |
| SK-notes_c | skidsolutions.eu/notes_c.md — Inaccessible sources; Other caveats | retain-limitations | [source-reconciliation.md](source-reconciliation.md): LV/LT procurement, EWC membership and Reddit coverage remain unknown. |
| SK-signals_section | skidsolutions.eu/signals_section.md — Signal tables | deduplicate | [source-reconciliation.md](source-reconciliation.md): Represented by canonical signals.csv; summaries/shards are not independent evidence. |
| ADJ-01 | _issues/eideasy/01-x509-hash-signed-request-objects.md — Summary; Proposed solution; Acceptance criteria; Notes | defer | [deferred candidates](#deferred-adjacent-wallet-candidates): Future wallet signed request, x5c/x509_hash, audience/SAN/response-host binding and opt-in unsigned testing behind FR-022. |
| ADJ-02 | _issues/eideasy/02-conformance-suite-and-reference-interop.md — Summary; Proposed solution; Acceptance criteria; Notes | adapt | [architecture.md](architecture.md): Honest versioned conformance evidence now; wallet execution only under FR-022/023. |
| ADJ-03 | _issues/eideasy/03-release-gated-verifier-deviation-table.md — Summary; Proposed solution; Acceptance criteria; Notes | adapt | [architecture.md](architecture.md): Release requirement/status/evidence/fix deviation disclosure; no borrowed test results. |
| ADJ-04 | _issues/eideasy/04-verifier-scope-and-limits-statement.md — Summary; Proposed solution; Acceptance criteria; Notes | adapt | [product-brief-eidbridge-2026-11-18.md](product-brief-eidbridge-2026-11-18.md): Assertion/trust limits and RP responsibilities, no QES/compliance claims. |
| ADJ-05 | _issues/eideasy/05-append-only-validation-audit-log.md — Summary; Proposed solution; Acceptance criteria; Notes | defer | [deferred candidates](#deferred-adjacent-wallet-candidates): Metadata audit conflicts with zero retention. Separate opt-in privacy ADR; local hash chain cannot prove truncation without external anchor. |
| ADJ-06 | _issues/eideasy/06-rp-registration-record-and-registrar-export.md — Summary; Proposed solution; Acceptance criteria; Notes | defer | [deferred candidates](#deferred-adjacent-wallet-candidates): Wallet per-RP intended-use/request ceilings and registrar export; no real submission or assumed national schema. |
| ADJ-07 | _issues/eideasy/07-dpia-outline-and-ropa-template.md — Summary; Proposed solution; Acceptance criteria; Notes | adapt | [PRD operations](prd.md#operations-requirements): Extend FR-013 with purpose/location/lifetime/evidence and deployer-completed DPIA/RoPA aid. |
| ADJ-08 | _issues/eideasy/08-incident-runbook.md — Summary; Proposed solution; Acceptance criteria; Notes | adapt | [PRD operations](prd.md#operations-requirements): FR-017 reason-code detect/contain/recover/notify, key compromise, stale trust and outage drills. |
| ADJ-09 | _issues/eideasy/09-production-deployment-guide.md — Summary; Proposed solution; Acceptance criteria; Notes | adapt | [PRD operations](prd.md#operations-requirements): HTTPS, explicit proxy-header trust, size limits, refuse test keys and ordered operator checklist; no zk-specific infrastructure. |
| ADJ-10 | _issues/eideasy/10-release-artifacts-and-container-image.md — Summary; Proposed solution; Acceptance criteria; Notes | adapt | [architecture.md](architecture.md): FR-001 source-build pins/checksum/SBOM/provenance and published-artifact smoke; reproducibility proved or variance disclosed. |
| ADJ-11 | _issues/eideasy/11-age-verification-integration-guide.md — Summary; Proposed solution; Acceptance criteria; Notes | defer | [deferred candidates](#deferred-adjacent-wallet-candidates): Future age predicate: not-proven does not mean underage or stable account identity. |
| ADJ-12 | _issues/eideasy/12-multiple-rp-identities-per-instance.md — Summary; Proposed solution; Acceptance criteria; Notes | defer | [deferred candidates](#deferred-adjacent-wallet-candidates): Future per-tenant keys/registration/ceilings, authenticated init/result and isolation; no hosted billing UI. |
| ADJ-13 | _issues/eideasy/13-openid4vp-to-oidc-bridge.md — Summary; Proposed solution; Acceptance criteria; Notes | adapt | [architecture.md](architecture.md): Reuse eidbridge issuer through method adapter, no duplicate OIDC server; pairwise identity needs actual evidence. |
| ADJ-14 | _issues/eideasy/14-plain-pid-presentation-path.md — Summary; Proposed solution; Acceptance criteria; Notes | defer | [deferred candidates](#deferred-adjacent-wallet-candidates): Wallet gate: SD-JWT/KB-JWT disclosure and mdoc transcript/holder/issuer/status verification, memory-only values; cross-project handoff not implementation. |
| ADJ-15 | _issues/eideasy/15-lotl-trust-list-refresh.md — Summary; Proposed solution; Acceptance criteria; Notes | defer | [deferred candidates](#deferred-adjacent-wallet-candidates): Profile-specific signed atomic trust updates/freshness/rollback; LOTL not assumed sufficient for all wallet trust domains. |
| ADJ-16 | _issues/eideasy/16-pkcs11-key-backend.md — Summary; Proposed solution; Acceptance criteria; Notes | defer | [deferred candidates](#deferred-adjacent-wallet-candidates): Optional demand-gated PKCS11/SoftHSM backend; default static binary remains CGO free. |
| ADJ-17 | _issues/eideasy/17-cms-plugin-wallet-acceptance.md — Summary; Proposed solution; Acceptance criteria; Notes | defer | [roadmap.md](roadmap.md): WooCommerce checkout age gate is separate from #30 WordPress login, cross-project reference only. |
| ADJ-18 | _issues/eideasy/18-wallet-authorised-remote-signing.md — Summary; Proposed solution; Acceptance criteria; Notes | defer | [deferred candidates](#deferred-adjacent-wallet-candidates): External CSC/QTSP transaction-bound orchestration differs from #28 digest relay; sandbox and legal review first. |
| EASY-NARR-1 | eideasy.com/RECOMMENDATION.md — Executive recommendation; C1–C5 | adapt | [source-reconciliation.md](source-reconciliation.md): Wallet candidates are gated alternatives; buyer interviews/raw demand precede expansion. |
| EASY-NARR-2 | eideasy.com/RECOMMENDATION.md — Scoring and sensitivity | context-only | [source-reconciliation.md](source-reconciliation.md): Shipping-risk scores and adjacent proxy costs do not establish eidbridge ROI. |
| EASY-NARR-3 | eideasy.com/RECOMMENDATION.md — 30-day plan | defer | [source-reconciliation.md](source-reconciliation.md): Three buyer interviews and two-of-three rejection pivot rule belong to wallet project, not current MVP. |
| EASY-NARR-4 | eideasy.com/RECOMMENDATION.md — Legal; Evidence gaps | retain-limitations | [source-reconciliation.md](source-reconciliation.md): Pricing/interop/legal interpretations not independently verified; no universal duty inferred. |
| EASY-NARR-5 | eideasy.com/RECOMMENDATION.md — Watch log; Automated pipeline | plan-only | [source-reconciliation.md](source-reconciliation.md): Weekly evidence diff/manual decisions designed only, no autonomous cron deployment. |
| EASY-LEGAL-01 | eideasy.com/legal/contributions-checklist.md — checklist row 1 | defer | [deferred candidates](#deferred-adjacent-wallet-candidates): Future wallet per-RP registration. |
| EASY-LEGAL-02 | eideasy.com/legal/contributions-checklist.md — checklist row 2 | defer | [deferred candidates](#deferred-adjacent-wallet-candidates): Future registered claim ceiling. |
| EASY-LEGAL-03 | eideasy.com/legal/contributions-checklist.md — checklist row 3 | defer | [deferred candidates](#deferred-adjacent-wallet-candidates): Metadata evidence requires separate retention decision. |
| EASY-LEGAL-04 | eideasy.com/legal/contributions-checklist.md — checklist row 4 | adapt | [PRD operations](prd.md#operations-requirements): Current data inventory/deployer DPIA aid. |
| EASY-LEGAL-05 | eideasy.com/legal/contributions-checklist.md — checklist row 5 | defer | [deferred candidates](#deferred-adjacent-wallet-candidates): Future profile-specific trust freshness. |
| EASY-LEGAL-06 | eideasy.com/legal/contributions-checklist.md — checklist row 6 | defer | [deferred candidates](#deferred-adjacent-wallet-candidates): Future minimal age predicate. |
| EASY-LEGAL-07 | eideasy.com/legal/contributions-checklist.md — checklist row 7 | adapt | [architecture.md](architecture.md): Current assertion/trust scope disclosure. |
| EASY-LEGAL-08 | eideasy.com/legal/contributions-checklist.md — checklist row 8 | adapt | [architecture.md](architecture.md): Current no-qualified-services claims. |
| EASY-LEGAL-09 | eideasy.com/legal/contributions-checklist.md — checklist row 9 | adapt | [architecture.md](architecture.md): Current versioned conformance disclosure. |
| EASY-LEGAL-10 | eideasy.com/legal/contributions-checklist.md — checklist row 10 | defer | [deferred candidates](#deferred-adjacent-wallet-candidates): Future registrar export without submission. |
| EASY-LEGAL-11 | eideasy.com/legal/contributions-checklist.md — checklist row 11 | adapt | [PRD operations](prd.md#operations-requirements): Current incident runbook. |
| EASY-LEGAL-12 | eideasy.com/legal/contributions-checklist.md — checklist row 12 | exclude | [deferred candidates](#deferred-adjacent-wallet-candidates): Qualified issuance/seals/QSCD outside product. |
| EASY-LEGAL-13 | eideasy.com/legal/contributions-checklist.md — checklist row 13 | exclude | [deferred candidates](#deferred-adjacent-wallet-candidates): Wallet certification outside product. |
| EASY-LEGAL-14 | eideasy.com/legal/contributions-checklist.md — checklist row 14 | defer | [architecture.md](architecture.md): Verifier licensing requires legal applicability review. |
| RANK-1 | rankings/RANKING.md — Ranking methodology | adapt | [source-reconciliation.md](source-reconciliation.md): Incumbent exposure is not user value, dependencies or feasibility; annual financial exposure unknown. |
| RANK-2 | rankings/RANKING.md — S1–S14 dossiers | adapt | [source-reconciliation.md](source-reconciliation.md): All map to requirements; S4 umbrella/not additive, S8 unofficial, S13 v2 only; signing legal statement overbroad. |
| RANK-3 | rankings/RANKING.md — Parked/excluded ledger | adapt | [source-reconciliation.md](source-reconciliation.md): Safety/conformance/release work stays mandatory even without a priced competitor surface. |
| RANK-4 | rankings/RANKING.md — E1–E9 and G1–G7 | adapt | [source-reconciliation.md](source-reconciliation.md): Wallet ideas have future gates; OSINT/proxy/browser work stays in original projects. |
| RANK-5 | rankings/RANKING.md — Implementation distance; queue | adapt | [source-reconciliation.md](source-reconciliation.md): No app implementation observed; other repos tests and overlapping synthetic queue are not progress. |
| GLAZER-recommendation | glazer.ee/deliverable/recommendation.md — Executive recommendation; plan; guardrails | exclude | [source-reconciliation.md](source-reconciliation.md): Evidence capture/RFC3161/WARC/proxy/OSINT/MCP/browser work belongs to fingerprintproxy/ManyFaces. |
| GLAZER-plan-30d | glazer.ee/deliverable/plan-30d.md — Executive recommendation; plan; guardrails | exclude | [source-reconciliation.md](source-reconciliation.md): Evidence capture/RFC3161/WARC/proxy/OSINT/MCP/browser work belongs to fingerprintproxy/ManyFaces. |
| GLAZER-compliance | glazer.ee/deliverable/compliance.md — Executive recommendation; plan; guardrails | exclude | [source-reconciliation.md](source-reconciliation.md): Evidence capture/RFC3161/WARC/proxy/OSINT/MCP/browser work belongs to fingerprintproxy/ManyFaces. |
| EXCLUDE-glazer-01 | _issues/glazer/01-fix-chunked-response-hang.md — Summary; Proposed solution | exclude | [source-reconciliation.md](source-reconciliation.md): Different product/data model; keep in original project, no eidbridge requirement. |
| EXCLUDE-glazer-02 | _issues/glazer/02-rfc3161-stamp.md — Summary; Proposed solution | exclude | [source-reconciliation.md](source-reconciliation.md): Different product/data model; keep in original project, no eidbridge requirement. |
| EXCLUDE-glazer-03 | _issues/glazer/03-verify-command.md — Summary; Proposed solution | exclude | [source-reconciliation.md](source-reconciliation.md): Different product/data model; keep in original project, no eidbridge requirement. |
| EXCLUDE-glazer-04 | _issues/glazer/04-verification-docs-demo-case.md — Summary; Proposed solution | exclude | [source-reconciliation.md](source-reconciliation.md): Different product/data model; keep in original project, no eidbridge requirement. |
| EXCLUDE-glazer-05 | _issues/glazer/05-refusal-records.md — Summary; Proposed solution | exclude | [source-reconciliation.md](source-reconciliation.md): Different product/data model; keep in original project, no eidbridge requirement. |
| EXCLUDE-glazer-06 | _issues/glazer/06-case-json-metadata.md — Summary; Proposed solution | exclude | [source-reconciliation.md](source-reconciliation.md): Different product/data model; keep in original project, no eidbridge requirement. |
| EXCLUDE-glazer-07 | _issues/glazer/07-redact-flag.md — Summary; Proposed solution | exclude | [source-reconciliation.md](source-reconciliation.md): Different product/data model; keep in original project, no eidbridge requirement. |
| EXCLUDE-glazer-08 | _issues/glazer/08-capture-retention.md — Summary; Proposed solution | exclude | [source-reconciliation.md](source-reconciliation.md): Different product/data model; keep in original project, no eidbridge requirement. |
| EXCLUDE-glazer-09 | _issues/glazer/09-capture-start-warning.md — Summary; Proposed solution | exclude | [source-reconciliation.md](source-reconciliation.md): Different product/data model; keep in original project, no eidbridge requirement. |
| EXCLUDE-glazer-10 | _issues/glazer/10-operator-obligations-docs.md — Summary; Proposed solution | exclude | [source-reconciliation.md](source-reconciliation.md): Different product/data model; keep in original project, no eidbridge requirement. |
| EXCLUDE-glazer-11 | _issues/glazer/11-mcp-server.md — Summary; Proposed solution | exclude | [source-reconciliation.md](source-reconciliation.md): Different product/data model; keep in original project, no eidbridge requirement. |
| EXCLUDE-glazer-12 | _issues/glazer/12-mcp-safety-policy.md — Summary; Proposed solution | exclude | [source-reconciliation.md](source-reconciliation.md): Different product/data model; keep in original project, no eidbridge requirement. |
| EXCLUDE-glazer-13 | _issues/glazer/13-mcp-agpl-source-offer.md — Summary; Proposed solution | exclude | [source-reconciliation.md](source-reconciliation.md): Different product/data model; keep in original project, no eidbridge requirement. |
| EXCLUDE-glazer-14 | _issues/glazer/14-fingerprint-coverage-metrics.md — Summary; Proposed solution | exclude | [source-reconciliation.md](source-reconciliation.md): Different product/data model; keep in original project, no eidbridge requirement. |
| EXCLUDE-glazer-15 | _issues/glazer/15-homebrew-release-verification.md — Summary; Proposed solution | exclude | [source-reconciliation.md](source-reconciliation.md): Different product/data model; keep in original project, no eidbridge requirement. |
| EXCLUDE-glazer-16 | _issues/glazer/16-capture-encryption-at-rest.md — Summary; Proposed solution | exclude | [source-reconciliation.md](source-reconciliation.md): Different product/data model; keep in original project, no eidbridge requirement. |
| EXCLUDE-glazer-17 | _issues/glazer/17-per-case-mitm-ca.md — Summary; Proposed solution | exclude | [source-reconciliation.md](source-reconciliation.md): Different product/data model; keep in original project, no eidbridge requirement. |
| EXCLUDE-glazer-18 | _issues/glazer/18-record-upstream-cert-chain.md — Summary; Proposed solution | exclude | [source-reconciliation.md](source-reconciliation.md): Different product/data model; keep in original project, no eidbridge requirement. |
| EXCLUDE-glazer-19 | _issues/glazer/19-warc-export.md — Summary; Proposed solution | exclude | [source-reconciliation.md](source-reconciliation.md): Different product/data model; keep in original project, no eidbridge requirement. |
| EXCLUDE-glazer-20 | _issues/glazer/20-enrichment-broker.md — Summary; Proposed solution | exclude | [source-reconciliation.md](source-reconciliation.md): Different product/data model; keep in original project, no eidbridge requirement. |
| EXCLUDE-manyfaces-21 | _issues/manyfaces/21-case-scoped-profiles.md — Summary; Proposed solution | exclude | [source-reconciliation.md](source-reconciliation.md): Different product/data model; keep in original project, no eidbridge requirement. |
| EXCLUDE-manyfaces-22 | _issues/manyfaces/22-case-screenshots.md — Summary; Proposed solution | exclude | [source-reconciliation.md](source-reconciliation.md): Different product/data model; keep in original project, no eidbridge requirement. |
| EXCLUDE-manyfaces-23 | _issues/manyfaces/23-remote-browser-isolation.md — Summary; Proposed solution | exclude | [source-reconciliation.md](source-reconciliation.md): Different product/data model; keep in original project, no eidbridge requirement. |
| PLAN-SPEC-PINS | skidsolutions.eu/plan_30d.md — Docs harvest; Do NOT build 8 | adapt | [source-reconciliation.md](source-reconciliation.md): Link/version/hash metadata only; no vendored unlicensed doc text or LGPL demo code. |
| PLAN-NODE | skidsolutions.eu/distribution.md — Exact hooks | exclude | [source-reconciliation.md](source-reconciliation.md): Link Node client, do not create competing SDK. |
| PLAN-COMMUNITY | skidsolutions.eu/distribution.md — Launch mechanics | plan-only | [source-reconciliation.md](source-reconciliation.md): Plan useful launch material; no HN/Reddit/tracker/Slack posts or catalogue PRs executed. |
| PLAN-METRICS | skidsolutions.eu/distribution.md — 90-day measurement | adapt | [source-reconciliation.md](source-reconciliation.md): Retain original metrics/failure-rule conflict with N-A handling, no product analytics. |
| PLAN-FALLBACK | skidsolutions.eu/plan_30d.md — Week 1 fallback ladder | adapt | [source-reconciliation.md](source-reconciliation.md): Notification same-product fallback; MID/Web eID requires explicit capacity/security decision, not automatic expansion. |
| PLAN-DATES | skidsolutions.eu/proposal.md — Executive recommendation; Evaluation protocol | retain-dated-hypothesis | [source-reconciliation.md](source-reconciliation.md): 2026-12-21/2027-01-11 source targets, 2027-02-14 fixed forecast resolution; launch D+90 starts at actual launch. |
| PLAN-REMEMBER | _issues/skid/20-method-chooser.md — Proposed solution | defer | [source-reconciliation.md](source-reconciliation.md): Method preference cookie opt-in after privacy/data-flow update, absent in single-method mode. |
| PLAN-PULL-METRICS | _issues/skid/26-doctor-health-check.md — Proposed solution | defer | [source-reconciliation.md](source-reconciliation.md): Counts/expiry metrics opt-in/pull-only/no personal data; no hosted monitoring. |
| PLAN-README-ET | _issues/skid/16-login-page-i18n.md — Notes | defer | [source-reconciliation.md](source-reconciliation.md): Estonian README optional, English authoritative; distinct from five required login catalogs. |
| PLAN-FRAMEWORKS | _issues/skid/18-framework-oidc-examples.md — Out of scope | defer | [source-reconciliation.md](source-reconciliation.md): Rails/Laravel/Spring additions only on demand. |
| PLAN-DEPLOYMENT | _issues/skid/14-compose-quickstart.md — Out of scope | defer | [source-reconciliation.md](source-reconciliation.md): Helm/systemd packaging only on demand; secure production guide still required. |
| PLAN-CSS | _issues/skid/07-binary-login-page-config.md — Out of scope | adapt | [source-reconciliation.md](source-reconciliation.md): Bounded CSS override only, no theming platform. |
| PLAN-SHARED-STORE | _issues/skid/10-no-telemetry-zero-retention.md — Out of scope | defer | [source-reconciliation.md](source-reconciliation.md): HA/shared store only on demand; document restart/single-replica now. |

## Source table detail

The roadmap lists all nine OPP candidates, fourteen S capabilities and fifteen synthetic source milestone IDs. Canonical signals (`research/competitive-signals.csv`, local only) preserve every dated evidence/caveat field. Watch (`research/competitive-watch.csv`, local only) preserves all source forecast columns with additional owner/review/status columns; no forecast is resolved early. Raw source evidence is referenced, not vendored.
