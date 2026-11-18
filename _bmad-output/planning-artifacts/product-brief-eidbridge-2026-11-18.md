---
title: eidbridge product brief
status: draft
created: 2026-11-18
updated: 2026-11-18
inputDocuments:
  - research/github-issues-2026-11-18.json
  - research/source-manifest.json
---

# eidbridge product brief

## Recommended product

A self-hosted, unofficial Go bridge makes verified Smart-ID RP API v3 authentication available as standard OIDC. Start with one method and a runnable demo; expand adoption through configuration guides rather than one plugin per IdP. Production operators retain their own scheme agreements, transaction charges, account policy and infrastructure responsibilities.

## Problem and differentiated outcome

The source research identifies manual broker onboarding, fragmented integration examples and a maintenance burden around API/TLS/trust changes. The proposed benefit is inspectable, deployer-controlled integration with no extra hosted broker layer, not elimination of eID service fees or a substitute for managed compliance/support. The same OIDC boundary serves existing IdPs and plain applications.

Source: skidsolutions.eu/proposal.md, Executive recommendation and Thesis attack; distribution.md, Exact hooks. Sources were frozen on 2026-11-16. Dated price comparisons are research context, not refreshed offers or verified savings. Transaction minimums, infrastructure and maintenance remain operator costs.

## Evidence strength and counter-case

The research demand dossier found four artifacts representing three distinct asks, including a duplicated e-residency thread. The asks are not three paying customers or three direct Smart-ID deployment commitments. Empty registry searches establish missing supply, not demand. State procurement awards describe incumbent service purchasing, not a competitive tender pipeline for this connector. The strongest alternative is a managed broker with support and contractual accountability; an official self-serve/free tier or native IdP support could remove much of the proposed advantage.

Sources: skidsolutions.eu/demand.md, Items found/Zero-result searches; procurement.md; oss_inventory.md; proposal.md, Thesis attack. Current GitHub backlog is 30 open issues retrieved on 2026-11-18, of which 12 are labelled deferred. The local tree contains BMAD/planning material; no application build or test pass is claimed.

## Product boundary

Initial release: verified v3 device-link path, optional v3 notification, OIDC code+PKCE, environment separation, no telemetry, in-memory personal flow data, protected logs, a demo and operator documentation. Next increment: config-only Keycloak/authentik/Zitadel/Ory kits and Django/FastAPI examples. Future methods and packages require their original demand, feasibility and security gates.

The bridge is not an identity issuer, qualified trust service, wallet, managed SaaS, transaction reseller or assurance certification. Authentication means the selected protocol checks passed against configured trust; certificate level and scheme labels do not by themselves prove legal assurance for every relying party. Scope and limits must be published per release, including unimplemented profile/status checks and deviations.

## Decisions that matter first

1. **Can a public demo flow be verified within the six-hour spike cap?** An observed result, sanitized fixtures and explicit automation limitations decide whether core implementation proceeds. Notification is a same-product fallback. Mobile-ID/Web eID alternatives require a separate project decision and estimate.
2. **Can the hardened issue scope fit available capacity?** Original issue estimates total 50–51 hours for issues 1–18, before overruns or translation review. At the source assumption of 10 hours/week that is at least 5.0–5.1 weeks, not the narrative four weeks. Use gates rather than silently cutting security.
3. **Is adoption sufficient to justify more protocol maintenance?** Keep 12 deferred issues gated. In particular, two concrete requests are required for a direct Python client; three unmet config-guide gaps for a Keycloak SPI. The broad multi-method competitor rank does not precede its dependencies.

## Outcomes and ownership

Maintainer owns protocol/fixture/build evidence; operator owns production configuration, keys, agreements and account linking; project owner owns capacity and expansion decisions. Localization reviewers own language quality. A future Web eID release requires external security review. Named individuals are not invented.

A prepared evaluator completes the demo within five minutes, an integrator can connect a documented OIDC client, and no test identity or secret leaks through logs or persistence. Market evidence is assessed manually from public counters and actual external adopters, with no product telemetry. Original source release targets are 2026-12-21 (core) and 2027-01-11 (kits); these are not newly confirmed commitments.

## Next planning surface

[PRD](prd.md) defines stable capabilities; [architecture](architecture.md) records boundaries and technical decisions; [epics](epics.md) preserves all acceptance criteria; [roadmap](roadmap.md) records sequencing, dates and reconsideration gates. See [source reconciliation](source-reconciliation.md) for every adopted, adapted, deferred or excluded idea.
