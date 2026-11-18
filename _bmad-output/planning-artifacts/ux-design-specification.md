---
title: eidbridge login UX requirements
status: draft
created: 2026-11-18
updated: 2026-11-18
inputDocuments:
  - research/github-issues-2026-11-18.json
  - research/source-manifest.json
---

# Login UX requirements

## Source and status

A behavior specification extracted from FR-004/007/011/014/016/020. No customer interview, usability test, final visual identity, prototype or native-speaker sign-off is claimed. Exact tokens/mockups can be supplied during design; do not block the initial technical spike on a fictional completed UX process.

## Flows and state model

Entry is a bound OIDC authorize transaction. Single-method mode starts directly at device-link. Desktop displays refreshing QR; mobile offers an explicit Open on this device control even when device detection is uncertain. A pending state presents instructions and bounded status; authentication success proceeds through code delivery, not an indefinite success page. Refusal, expiry, invalid input, upstream unavailable and verification failure end in a terminal state. The outcome page returns the user to the client, and a fresh attempt is a new authorize request that never reuses the old challenge. Status polling is authenticated by the flow context and cannot disclose other sessions.

~~~mermaid
stateDiagram-v2
  [*] --> Created: bound authorize request
  Created --> Pending: QR page loads, upstream session created
  Created --> Failed: upstream init error
  Created --> Cancelled: user cancels
  Created --> Expired: code TTL passes
  Pending --> Verified: cryptographic checks pass, code issued
  Pending --> Refused
  Pending --> Expired
  Pending --> Failed
  Pending --> Cancelled
  Verified --> [*]: redirect to client, single-use code exchange follows
  Refused --> [*]: outcome page and return link
  Expired --> [*]: outcome page and return link
  Failed --> [*]: outcome page and return link
  Cancelled --> [*]: outcome page and return link
~~~

Verification-code comparison must match the active challenge and on-device interaction. Never show completion from an old flow. A scheme-level failure maps to localized actionable text without exposing raw identifiers, certificates, endpoint bodies or secrets. Do not claim that scanning a demo proves a real person.

## UX design requirements

- **UX-DR-001:** Dynamic desktop QR and same-device button reflect one bounded flow; stale QR/late completion cannot revive it.
- **UX-DR-002:** Waiting, code comparison, refusal, timeout, invalid input, retry and upstream failure have distinct localized accessible text with no personal-data errors.
- **UX-DR-003:** Persistent demo banner and unofficial footer; production examples reject demo assertions.
- **UX-DR-004:** Keyboard access, visible focus, associated labels, bounded status announcements and no focus theft on QR refresh; axe covers success/error screens.
- **UX-DR-005:** ui_locales then Accept-Language then configured default; html lang and locale persist across handoff/errors; include ru from issue body.
- **UX-DR-006:** Notification requires explicit enablement, country/checksum validation, anti-enumeration response and per-client/IP rate control.
- **UX-DR-007:** Future chooser respects client methods/assurance, bypasses single-method step; preference cookie is opt-in/non-identifying/short-lived.
- **UX-DR-008:** Neutral server-rendered visual treatment, accessible contrast, no scheme logos/copied UI/tracking assets; final design tokens remain design work.

## Components and layout contract

One server-rendered page family: neutral title/context, persistent demo banner when applicable, primary QR/same-device area, status/instructions, optional notification form, locale links and unofficial notice. Separate reusable components: DemoBanner, DeviceLinkPanel, VerificationCode, StatusMessage, NotificationForm, LocaleSwitcher and future MethodChooser. Use semantic HTML/associated labels, readable focus indicators and contrast; final colors/type/spacing are design choices to test, not scheme-branded assets. A permitted CSS override must not hide mandatory warnings or remove keyboard focus.

No framework or external analytics assets. CSP without unsafe-inline requires nonce/hash or external self-hosted script handling to be designed with the small polling/QR script. Screen-reader status updates must avoid re-announcing every poll. QR renewal does not steal keyboard focus. Display a textual same-device fallback and clear waiting/expired states; never rely on color alone.

## Locale and scope resolution

Issue #16 title lists four languages but body requires en/et/lv/lt/ru: preserve all five. Precedence ui_locales → Accept-Language → EIDBRIDGE_DEFAULT_LOCALE (default en). Maintain language across redirect/poll/error; chosen interaction language must respect actual upstream support. Validate per-client display_text length against the pinned protocol, reject invalid config. Missing keys fail CI; native-speaker review is required, not presumed.

Notification mode is default-off; validation and rate limits apply before outbound requests. Do not prefill identity data from untrusted login_hint or log the form. Chooser and remembered preference are future scope. Only the registry contract test uses a fake method; the chooser activates with the real second method; apply per-client allowed_methods, supported assurance filtering, explicit selection and keyboard operation. Unknown or disallowed method/assurance must fail safely rather than silently lower assurance.

## Acceptance evidence

FR-007 requires no serious axe-core violations; test every visible terminal/error mode, keyboard order and focus retention, mobile same-device and desktop QR. FR-011 requires demo banner/template tests and token assertions. FR-014 measures clean-clone QR and the prepared five-minute login, recording registration prerequisites separately. FR-016 requires catalog parity and native review. FR-020 tests filters/preselection/permissions/amr and single-method bypass only after activation. These tests are planned; none ran in this documentation task.
