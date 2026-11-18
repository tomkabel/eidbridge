---
title: architecture.md remediation plan
status: draft
created: 2026-11-18
inputDocuments:
  - architecture.md
  - /tmp/eidbridge-architecture-review.json (copied to research/ in Phase 0)
---

# Architecture remediation plan

## Goal beyond the goal

Make the architecture something two independent implementers would build the same way, and that a reviewer can prove is safe. Fixing the wording that got flagged is not enough on its own: each normative rule must trace to a decision, a story acceptance criterion (AC) and a named test.

## Ambition types

- **Altitude:** used. The finding list is a symptom. The goal is a document that stays correct as epics and code change.
- **Depth:** used. Most findings are security-critical OIDC and eID behavior, and the fixes have to meet the RFC and specification bar, not a "sounds reasonable" bar.
- **Range:** used narrowly. Four disciplines each own a slice: protocol security, SRE, privacy engineering and technical editing. No extra deliverables come from them.

## Altitude ladder

1. **Close every finding.** Each of the 82 IDs below gets a decision, an edited section and a verifying AC.
2. **Make the design decision-ready.** Replace prose rules with normative artifacts: a state-transition table, a data-lifecycle table, a configuration-invariant matrix and a capacity model. Push each rule into PRD NFRs and epic story ACs so implementation cannot drift.
3. **Make the planning set self-checking.** `tools/check-arch-trace` fails CI when any review finding lacks an architecture anchor plus AC, or when the editorial gates regress. A future review then starts from a clean, mechanically verified baseline.

Rung 3 is the target. It is small: one script and one CI job, using the `tools/` directory that already exists.

## Depth

- **What a top eID/OIDC architect would add:**
  - Check the design against RFC 9700 (OAuth 2.0 Security BCP), OIDC Core and RFC 9207 (`iss` in the authorization response, the mix-up defense nobody flagged).
  - Write the state machine and the data lifecycle as tables that become test fixtures.
  - Derive the capacity limits from a load model instead of quoting 10,000.
  - Make different failures of the same kind distinguishable: compromise versus rotation, overload versus outage.
- **Rawest material:**
  - The pinned Smart-ID RP API v3 documentation: `endResult` codes, the session-status long-poll semantics, and the device-link and Web2App callback parameters.
  - The RFC and OIDC texts listed above.
  - The PRD NFRs and the epic ACs (`prd.md:289-302`, `epics.md`).
  - Not this review's summary.
- **Methods:**
  - An RFC 9700 section-by-section checklist.
  - An exhaustive transition table with an "unknown input fails closed" row.
  - LINDDUN-style linkability analysis for `sub`.
  - Little's-law sizing for the flow store and upstream concurrency.
  - A Microsoft Writing Style Guide edit pass.
- **Outside judges (pass criteria in Phase 6):**
  - The trace script.
  - A blind re-review with no prior findings.
  - Grep-based style gates.
  - A Mermaid render.
  - The bmad implementation-readiness check.
  - At implementation time, the OIDF Basic OP plan.
- **Hard target:**
  - Zero recurrence of the 40 behavioral findings in a blind adversarial and edge-case re-review.
  - Zero new findings in their classes.
  - The document at about 1,900 words or less, excluding tables.

## Range

| Field | Concrete job | Method or tool |
|---|---|---|
| Protocol security engineer | Token, `sub`, key and authorize-parameter decisions (Phase 1) | RFC 9700/OIDC Core checklist, RFC 9068/9207/8725 |
| SRE | Capacity, poller, readiness, shutdown, clock (Phase 2) | Little's law, failure-mode table, `time.Since` monotonic rules |
| Privacy engineer | `sub` derivation, claim lifecycle, userinfo source (Phase 1) | LINDDUN linkability, data-lifecycle table |
| Technical editor | Structure and prose (Phases 3–4) | Microsoft Writing Style Guide, `word_metrics.py`, grep gates |

## Data, tools and access

| Need | Status |
|---|---|
| `architecture.md`, `prd.md`, `addendum.md`, `epics.md`, `source-reconciliation.md` | There |
| Review findings JSON | There, but in `/tmp`, which is volatile. Phase 0 copies it into the repo |
| Smart-ID RP API v3 documentation (`endResult`, long-poll, callback parameters) | Missing locally. Fetchable with self-hosted Firecrawl. Q-01 owns the final values |
| RFC 9700, 9207, 9068, 8725, 7636 and OIDC Core texts | Fetchable with Firecrawl. Store as spec-pin metadata only (ADR-004) |
| bmad-review and bmad readiness skills | There |
| Mermaid CLI for the render gate | Unknown; check `npx @mermaid-js/mermaid-cli` |

## Resolved without user input

The four ambiguous prose items are answered by the PRD:

- **"product wedge"** means the Smart-ID→OIDC product focus (PRD A-01).
- **"Banner repeats per source"** means a persistent demo banner on every login page (UX-DR-003).
- **"Latest minor fixes"** means fixes ship in the latest minor release, and trust fixes are backported one minor release, subject to capacity (NFR-013).
- **"necessary/allow-listed"** becomes "only when the client is allow-listed".

## Phases

Each phase ends with its own check. Finding IDs come from Phase 0: A01–A17 are adversarial findings and E01–E23 are edge-case findings, both in JSON order. S01–S17 are structure findings and P01–P25 are prose findings, both in report order.

### Phase 0: Ground truth and traceability (about 1 hour)

1. Copy the review JSON to `research/architecture-review-2026-11-18.json` and add `id` fields. Also record the structure and prose rows as S and P entries.
2. Fetch and pin the specification metadata (URL, version, hash, license) for:
   - Smart-ID v3: session status, `endResult` values, device-link and Web2App callback parameters.
   - RFC 9700, 9207, 9068, 8725 and OIDC Core §3.1.2.1, §3.1.2.6, §5.5.1.1 and §16.
3. Write `tools/check-arch-trace`. It fails while any finding ID lacks a row in architecture.md's "Review resolution" appendix with a section anchor and a story AC reference.

**Gate:** the script runs and fails with all 82 findings open.

### Phase 1: Security-critical decisions (new ADRs; the "Public surface" section becomes ADR-007 and ADR-008)

**ADR-007: Subject and key management** (A03, A04, A05, E12, E13, E14, E22)

- `sub = base64url(HMAC-SHA256(K_sub[v], sector ‖ country ‖ code))`.
  - Public mode uses one global sector; pairwise mode uses one sector per client.
  - A raw or plainly hashed personal code is never a `sub`.
  - Fix `addendum.md:195` to match.
- `K_sub` is versioned. The version is stored in config and never rotated in place.
  - Rotation is a migration: during the window, tokens carry both `sub` and `previous_sub`, so clients can relink accounts at the next login.
  - Changing a client's `sub_mode` is rejected unless the same migration is declared.
  - `K_sub` is backed up under the same custody as the signing key.
- Signing keys have two procedures:
  - **Planned rotation:** the retired public key stays in JWKS until the longest token expiry plus clock skew. Retired keys persist with a `not_after` time, so they survive restarts.
  - **Emergency revocation:** remove the key from JWKS immediately, rotate the access-token sealing key, and require clients to re-authenticate.
  - The recovery drill exercises both.
- `id_token_signed_response_alg` is set per client, defaulting to RS256. Registering an unsupported algorithm fails at startup.

**ADR-008: Token model and authorize contract** (A01, A02, A06, A07, E07, E08, E09)

- Access tokens are opaque to clients: claims are sealed with AEAD under a versioned bridge key.
  - userinfo decrypts and returns exactly the claims the client is authorized for.
  - The configurable TTL is 5 minutes or less.
  - There is no server-side claim cache, so ADR-002's "encrypted" wording becomes true where it now applies (A01). Fix the ADR-002 sentence to "plaintext in process memory, keyed by the code hash".
  - `personal_code` appears only for allow-listed clients.
- Codes are consumed with an atomic `LoadAndDelete`.
  - Any failed exchange (PKCE, client authentication or `redirect_uri`) still consumes the code (RFC 6749 §4.1.2, RFC 9700 §2.1.1).
  - A replayed code adds its token-family ID to a bounded in-memory deny-list, held for the maximum access-token TTL. userinfo rejects tokens in that family. This meets the OIDC revoke-on-replay rule without persistence.
- `private_key_jwt` accepts inline static client JWKS only, with no `jwks_uri` fetching. Q-03 decides whether `private_key_jwt` ships in v1 at all.
- Authorize parameters:
  - Requested `acr_values` that cannot be proven fail with `unmet_authentication_requirements`; the bridge never silently downgrades.
  - `prompt=none` returns `login_required`, because there are no bridge sessions.
  - Every login is fresh, so `max_age` is always met and `auth_time` is always set.
  - The authorization response includes `iss` (RFC 9207), and the discovery document advertises it.
  - Error redirects happen only after the client and `redirect_uri` are validated.

**ADR-003 additions** (A12, E16, E17, E18)

- Mode is required, with no default; startup fails if it is unset.
- Demo mode rejects production hosts, pins, CA and RP UUID, and production mode rejects the demo equivalents.
- Demo uses a distinct issuer path and an auto-generated signing key labelled as demo. Production refuses any key whose fingerprint appears in the demo keystore.
- `TLS_PINS=disabled` in production also requires an explicit acknowledgement flag and emits the deviation record. Without the flag, startup fails.
- Startup warns when no trusted proxy is configured and every peer address is private or a load balancer. The rate-limit key is the resolved client IP.

**Gate:** IDs A01–A07, A12, E07–E09, E12–E14, E16–E18 and E22 pass the trace script. Self-check every ADR against the RFC 9700 checklist; the gaps it finds go into the deviation table.

### Phase 2: Behavior closure (normative tables in ADR-002 and a new ADR-009)

**Flow state machine table** (E01, E02, E03, E06, E15)

- The states are `created`, `pending`, `verified`, `refused`, `expired`, `failed` and `cancelled`.
- Every input × state cell is defined: upstream init error, browser abandon, poll result, poll-retry exhaustion, timeout, identity mismatch and late result.
- Every `endResult` value from the pinned specification maps to a state, and any unknown value maps to `failed`.
- A late result arriving for a missing or terminal entry is discarded, and its secrets are destroyed.
- An identity mismatch moves the flow to `failed(identity_mismatch)` and never issues a code.

**Data-lifecycle table** (S12, A01, E10)

- Columns are item, created, destroyed at, and memory owner.
- Rows are: flow entry, challenge and certificate secrets, claim set, code, sealed access token, replay deny-list entry and cookies.
- Cookies are cleared on every terminal state.

**ADR-009: Capacity and availability** (A08, A09, A13, A14, E04, E05, E19, E20, E21)

- Pending-flow cap: 10,000 (NFR-003). The code store has its own cap, and a code slot is reserved when the flow is created, so a verified flow always gets a code.
- Per-IP and per-client token buckets apply inside the global cap. Overflow returns 503 with `Retry-After`, and entries are never evicted.
- The upstream session is created when the QR page loads, not when the authorize request arrives.
- One server-side poller handles upstream polling, with a global concurrency semaphore and a rate limit sized from the RP quota (Little's law: concurrency = rate × mean session time). The browser polls only local state. An abandoned flow cancels its upstream poll.
- Readiness checks only config and key load. Capacity saturation is a 503 on the individual request, never a readiness failure. Readiness goes not-ready only during a SIGTERM drain.
- On SIGTERM: stop accepting new authorize requests, drain until the 60-second code TTL or the grace period ends, then exit.
- An unknown flow handle (for example, after a restart) shows a stable error page and redirects `error=access_denied` to the validated `redirect_uri`.
- All TTLs use the monotonic clock.

**ADR-010: Browser binding** (A10, E11, E23)

- There is one cookie per flow, named `__Host-eidb-<flow-id>`, with Secure, HttpOnly, SameSite=Lax, `Path=/` and Max-Age equal to the flow TTL. This lets two tabs run independent flows.
- Cross-browser Web2App return: if the pinned v3 callback carries verifiable parameters, bind with a one-use server handle plus those parameters. Otherwise fail with a restart page. Q-01 records which case applies, and this ADR must not invent parameters.
- The remember-method cookie is ignored when its method is no longer in the registry.

**Threat table additions** (A11)

- QR relay: dynamic QR freshness, the verification code shown on screen, the bridge origin displayed, and a relay-attempt test.
- UI injection and framing: a strict CSP, `frame-ancestors 'none'`, template autoescaping, and a header test.
- Mix-up attack: the RFC 9207 `iss` parameter.

**Diagram** (A15): add the browser→bridge front channel and the eID app→Smart-ID leg, plus trust-boundary groupings for the user device, the operator host and the scheme.

**Gate:** all of E01–E23 and A08–A11, A13–A15 trace. Every cell in the state-machine table has a defined outcome.

### Phase 3: Structure (S01–S17)

- Add the decision index at the top. Its columns are ADR, decision, status, Q-xx, owner, blocking FR or story, and evidence. This covers A16 and S03.
- Fix ADR-006: until a demand trigger arrives, only the registry contract test with a fake method exists. The chooser UI and FR-019 activate together (A17).
- Restructure each ADR with the lead-ins Status, Decision, Source reconciliation, and Open gates and evidence.
- Move the threat model ahead of the ADRs.
- Move the ADJ table and the ADJ-17 paragraph to `source-reconciliation.md`, leaving a two-sentence pointer.
- Move the ADR-005 operator-docs and production-checklist paragraphs to the PRD operations section, leaving a one-sentence pointer.
- Turn the layout into a list and the per-release table into a template.
- Add a glossary, or link the PRD glossary.
- Link the FR, Q and issue IDs.
- Cut the duplicate and process-note passages (S08–S11).
- Add a lead-in sentence for the Mermaid diagram.

**Gate:** `word_metrics.py` reports about 1,900 words or less outside tables, and every anchor referenced by the trace still resolves.

### Phase 4: Prose (P01–P25)

- Apply the prose table edits, with the four ambiguous items resolved as above.
- Define "source" once in the Status section.
- Use US spelling, serial commas and code formatting for literals.
- Replace "and/or" slashes with "and" or "or".

**Gate:** grep finds zero matches for `licen[cs]e` with the `c` spelling, for `labelling`, and for `80–100h`. No `acr=demo` or `TLS_PINS` appears outside backticks.

### Phase 5: Propagation

- **`prd.md`:**
  - Add the code-store cap, per-IP and per-client quotas, and the readiness definition to NFR-003 and NFR-014.
  - Add mode-required and demo-key separation to NFR-007, and pin-disable acknowledgement to NFR-006.
  - Fix A-01 wording if needed.
- **`addendum.md:195`:** the HMAC `sub`.
- **`epics.md`:** update the ACs for these stories, and cite each new AC in the trace appendix:
  - 2.3: fake method contract only.
  - 2.4: token model, `iss`, authorize parameters, alg per client.
  - 2.5: cookies, poller, capacity, restart page.
  - 2.6: lifecycle and deny-list.
  - 2.7: mode and demo key.
  - 3.4: rotation versus compromise drill.
  - 4.1: chooser gate and stale remember cookie.
- Rerun the implementation-readiness check and replace `implementation-readiness-report-2026-11-18.md`.

**Gate:** the readiness check passes and the trace script passes on all 82 findings.

### Phase 6: Outside judges (pass criteria)

1. `tools/check-arch-trace` exits 0.
2. A blind `bmad-review` (adversarial plus edge-case) of the revised `architecture.md` runs without the prior findings. Pass means none of the 40 behavioral findings recur and there is no new finding in the same classes. Any other new findings are triaged into the deviation table or fixed.
3. The style grep gates pass and the Mermaid diagram renders.
4. The readiness report is green.
5. Deferred to implementation: the OIDF Basic OP plan and the RFC 9700 checklist recorded per ADR-005 as PASS, FAIL or NOT RUN.

## Traceability

| Finding IDs | Phase and home |
|---|---|
| A03 A04 A05 E12 E13 E14 E22 | P1 ADR-007 |
| A01 A02 A06 A07 E07 E08 E09 | P1 ADR-008 (+ ADR-002 wording) |
| A12 E16 E17 E18 | P1 ADR-003 |
| E01 E02 E03 E06 E15 E10 | P2 state and lifecycle tables |
| A08 A09 A13 A14 E04 E05 E19 E20 E21 | P2 ADR-009 |
| A10 E11 E23 | P2 ADR-010 |
| A11 A15 | P2 threat table and diagram |
| A16 A17 S01–S17 | P3 |
| P01–P25 | P4 |

## Rewritten prompt

```text
Remediate _bmad-output/planning-artifacts/architecture.md against all 82 findings from the 2026-11-18 review (JSON in research/, structure/prose in this plan). Work as a protocol security engineer, SRE, privacy engineer and technical editor would: pin the Smart-ID v3 and RFC 9700/9207/9068/8725/OIDC Core sources first, then write normative tables (state machine with fail-closed unknowns, data lifecycle, config invariants, capacity sized by Little's law) instead of prose rules. Add ADR-007 subject/keys, ADR-008 token model, ADR-009 capacity/availability, ADR-010 browser binding; propagate rules into prd.md NFRs, addendum.md:195 and epics.md story ACs. Pass = tools/check-arch-trace exits 0 for every finding, a blind adversarial+edge-case re-review reproduces none of the 40 behavioral findings, style grep gates and the Mermaid render pass, and the readiness check is green.
```

## Next

Start at Phase 0. All the access it needs is available: Firecrawl for the specifications and the local repo. Phases 1–5 edit the planning docs, which is reversible. No step spends money or publishes anything.
