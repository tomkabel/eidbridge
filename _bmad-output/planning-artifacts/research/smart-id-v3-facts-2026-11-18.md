# Smart-ID RP API v3 facts (pinned 2026-11-18)

Own-words paraphrase of the pinned SK ID Solutions docs. Pin metadata and sha256 values: `docs/spec-pins/spec-pins.json` (ids in brackets below). Docs version printed on the site: **Relying Party API 3.2.8**. Anything not found in the fetched pages is written "NOT FOUND in pinned docs".

Base URL for all pages: `https://sk-eid.github.io/smart-id-documentation/`. Short names used below:

| Short | URL | pin id |
|---|---|---|
| YAML | `_/static/RP-API_V3.yml` (OpenAPI; `info.version` reads "3.1", docs site is 3.2.8) | smartid-rp-api-v3-openapi-yaml |
| API-SPEC | `rp-api/api_specification.html` (rendered form of the YAML; session operation anchor `#tag/session-endpoint/GET/v3/session/{sessionID}`) | smartid-rp-api-v3-openapi-page |
| OVERVIEW | `rp-api/overview_of_api_endpoints.html` | smartid-rp-api-v3-overview-of-endpoints |
| DLF | `rp-api/device_link_flows.html` | smartid-rp-api-v3-device-link-flows |
| AUTHCODE | `rp-api/authcode.html` | smartid-rp-api-v3-authcode |
| NOTIF | `rp-api/notification_based_flows.html` | smartid-rp-api-v3-notification-based-flows |
| CALLBACK | `rp-api/callback_urls.html` | smartid-rp-api-v3-callback-urls |
| RESP-VER | `rp-api/response_verification.html` | smartid-rp-api-v3-response-verification |
| SIGPROTO | `rp-api/signature_protocols.html` | smartid-rp-api-v3-signature-protocols |
| API-DETAILS | `rp-api/api_details.html` | smartid-rp-api-v3-api-details |
| UX | `user_experience.html` | smartid-rp-api-v3-user-experience |
| CHANGES | `rp-api/changes.html` | smartid-rp-api-v3-changelog |
| INTRO | `rp-api/introduction.html` | smartid-rp-api-v3-introduction |

Known inconsistencies inside the pinned sources (carry into ADRs as risks):
- YAML `info.version` is "3.1" while the site header says 3.2.8.
- YAML `endResult` enum has 11 values; its description text also lists `ACCOUNT_UNUSABLE` (see 1b).

---

## 1. Session status: `state` and `result.endResult`

Source: `GET /v3/session/{sessionID}` response schema in YAML (API-SPEC, session endpoint anchor). Not documented as prose elsewhere.

### 1a. `state` (2 values)

| value | meaning |
|---|---|
| `RUNNING` | Session not finished. `result` may be empty or absent. |
| `COMPLETE` | Session finished; `result.endResult` tells how. Only `OK` is success. |

Other response fields (YAML): `result.documentNumber` (mandatory when `OK`), `result.details.interaction` (names the refused interaction for `USER_REFUSED_INTERACTION`), `signatureProtocol`, `signature`, `cert` (mandatory when `OK`), `interactionTypeUsed` (mandatory when `OK`), `deviceIpAddress` (only if requested via `requestProperties.shareMdClientIpAddress`), `ignoredProperties`, and `deviceLinkRegistered`.
`deviceLinkRegistered` (boolean): present only in device-link flows (`QR`/`Web2App`/`App2App`); true once the user has interacted with the device link and the transaction was created; absent for notification flows.
Clients must ignore unknown JSON fields at any depth (API-DETAILS, "API client must ignore unknown names").

### 1b. `result.endResult` (11 enum values + 1 description-only value)

| value | meaning |
|---|---|
| `OK` | Success; certificate, document number and (where applicable) signature are returned. |
| `USER_REFUSED` | User declined the session, other than on the interaction screen. |
| `TIMEOUT` | User neither confirmed nor refused within the allowed time. Duration: NOT FOUND in pinned docs. |
| `DOCUMENT_UNUSABLE` | This request cannot be completed for the document/account; user told to check the app or contact support. |
| `WRONG_VC` | In a multiple-choice verification-code interaction the user picked the wrong code. |
| `REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP` | Installed app supports none of the interactions the RP listed. |
| `USER_REFUSED_CERT_CHOICE` | User has several accounts and pressed Cancel on the device-choice screen. |
| `USER_REFUSED_INTERACTION` | User pressed cancel on the interaction screen (except during certificate-choice device selection); refused interaction named in `result.details.interaction`. |
| `PROTOCOL_FAILURE` | Logical error in the signing protocol. |
| `EXPECTED_LINKED_SESSION` | The app got a different transaction while it was waiting for the linked session that follows a device-link certificate-choice session. |
| `SERVER_ERROR` | Process ended because of a server-side technical error. |
| `ACCOUNT_UNUSABLE` | Account currently unusable. **Appears only in the YAML description text, not in the enum list** (inconsistency). |

Legacy codes (v2: `USER_REFUSED_DISPLAYTEXTANDPIN`, `USER_REFUSED_VC_CHOICE`, `USER_REFUSED_CONFIRMATIONMESSAGE`, `USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE`) were folded into `USER_REFUSED_INTERACTION` in 3.1 (CHANGES, "RP API version 3.1 changes compared to version 2", "New features / API endpoint and parameter changes").

HTTP-level outcomes on the session endpoint (YAML): `200`, `400` (malformed; repeating unchanged will fail), `401` (source IP + `relyingPartyUUID` combination wrong), `404` ("session does not exist or has expired"), `480` (RP client too old), `580` (system under maintenance). Errors use RFC 9457 format (API-DETAILS "Error details"). RPs should not show different UI messages for different error causes, to hinder enumeration (API-DETAILS).

---

## 2. Long-poll semantics

- Endpoint is described as an asynchronous long-poll: it may not return until a timeout expires; the caller may tune parameters "inside the bounds set by the service operator" (YAML, tag "Session endpoint" description; API-SPEC).
- Query parameter `timeoutMs` (optional integer): schema minimum 1000, maximum 120000, default 60500 (described as halfway between min and max) (YAML, `components/parameters/timeoutMs`; API-SPEC). Whether the live server enforces the same bounds: NOT FOUND in pinned docs (only "bounds set by the service operator").
- A response with `state: RUNNING` is the documented "session not finished yet" shape (YAML example `RunningSessionResponseExample`: body is just `state: RUNNING`). That a RUNNING reply means "the long-poll window elapsed, poll again" is not spelled out: NOT FOUND in pinned docs as explicit text.
- Polling may start before or after the user returns through the callback URL; verification itself must wait until the user is back for Web2App/App2App (CALLBACK, Web2App step 7-8; RESP-VER step 1).
- Rate limits / quotas / recommended poll cadence / back-off: NOT FOUND in pinned docs.
- Session-creation idempotency: repeating `signature/certificate-choice` or `signature` creation with identical parameters within 15 seconds may return the existing session id; `nonce` overrides this and is not allowed on authentication requests, which must carry a fresh random `rpChallenge` instead (API-DETAILS, "Idempotent behaviour", anchor `#idempotent_behaviour`).
- `rpChallenge`: random value, 32-64 bytes, Base64, freshly generated per authentication (YAML, `rpChallenge` property; SIGPROTO "rpChallenge generation").

---

## 3. Device link, QR and Web2App flow

### 3a. What the RP API returns on session creation (DLF `#_device_link_calculation`; YAML `DeviceLinkResponse`)
`sessionID` (UUID), `sessionToken` (URL-safe, min 24 chars), `sessionSecret` (Base64 key; must never reach the RP frontend), `deviceLinkBase` (URL base to build links).

### 3b. Parameters on the link (DLF `#_device_link_parameters`)
Same-device link (Web2App/App2App):
`<deviceLinkBase>?deviceLinkType=<..>&sessionToken=<..>&sessionType=<..>&version=<..>&lang=<..>&authCode=<..>`
QR link adds `elapsedSeconds` (second parameter in the documented example, right after `deviceLinkType`).

| param | content |
|---|---|
| `deviceLinkType` | `QR`, `Web2App` or `App2App` |
| `sessionType` | `auth`, `sign` or `cert` |
| `version` | `1.0` (only value) |
| `elapsedSeconds` | seconds since the session-creation response arrived; QR only |
| `lang` | ISO 639-2 three-letter code; only affects the HTTPS fallback page |
| `authCode` | Base64URL(HMAC-SHA256(Base64-decoded `sessionSecret`, `authCodePayload`)) (AUTHCODE `#_authcode_parameter`) |

`authCodePayload` for authentication is the UTF-8 join with `|` of: `smart-id` (scheme name; `smart-id-demo` in demo), `ACSP_V2`, `rpChallenge`, Base64(`relyingPartyName`), Base64(`brokeredRpName`, empty unless brokering), `interactions` (Base64 string exactly as sent), `initialCallbackUrl` (empty for QR), `unprotectedDeviceLink` (link without `authCode`) (AUTHCODE). Link rules: no URL encoding, no fragment, fixed parameter order, case-sensitive, bit-exact match required (DLF IMPORTANT box). The link must be computed in the RP backend; frontend must not influence any value; `authCode` values must not be pre-computed and pushed ahead of time (DLF IMPORTANT box).
Environments page gives `schemeName` per environment (`environments.html`, pin smartid-environments).

### 3c. Does the dynamic QR change over time? Yes.
- `elapsedSeconds` changes, so `authCode` and the link change; the QR must be regenerated every 1 second in the RP backend (DLF `#_device_link_calculation`, `#_elapsedseconds_parameter`).
- UI guidance: refresh each second over a 60-second period, and never show a QR older than 3 seconds (UX, step "Show instructions", cross-device). These are UX recommendations; a server-enforced QR TTL or rejection rule for stale `elapsedSeconds`: NOT FOUND in pinned docs.
- Same-device (Web2App/App2App) links carry no `elapsedSeconds` and "should not be dynamically regenerated" (DLF note box).

### 3d. Verification code shown to the user
- Device-link flows: no verification code is part of the documented flow. INTRO says same-device device-link means the user does not have to compare VCs; OVERVIEW says the linked flow shows no VC; NOTIF and the glossary scope VCs to notification flows only (`rp-api/glossary.html` "Verification Code (VC)", pin smartid-rp-api-v3-glossary).
- Notification authentication: the RP computes a 4-digit VC from the raw `rpChallenge` bytes: SHA-256, take the last two bytes as a big-endian unsigned integer, mod 10000, zero-pad to 4 digits; show it in the browser and tell the user to proceed only if it matches the phone (NOTIF `#verification_codes_for_authentication_requests`).
- Notification signature: VC is returned by the server (`vc`, type `numeric4`) and shown as received (NOTIF `#verification_codes_for_signature_requests`).
- `confirmationMessageAndVerificationCodeChoice` interaction is notification-flow only (`rp-api/interactions.html` visualization note).

### 3e. Web2App / App2App callback (CALLBACK `#_web2app_callback_url`, `#_app2app_callback_url`)
RP-supplied `initialCallbackUrl` (YAML `InitialCallbackUrl`: HTTPS only, no `#`, max 1800 chars, must differ between Web2App and App2App, must contain a unique unpredictable RP-generated query parameter, must be empty for QR). After the user finishes (the page says signed or rejected), the app opens the callback URL (top-level GET, new tab) with parameters added by the Smart-ID app:
- `sessionSecretDigest`: Base64URL(SHA-256(`sessionSecret`)).
- `userChallengeVerifier`: URL-safe random string; authentication only. The session status `signature.userChallenge` equals Base64URL(SHA-256(`userChallengeVerifier`)) (YAML `userChallenge`; RESP-VER step 3; CHANGES 3.2.8 clarifies the verifier is URL-safe random characters, not a Base64 string).
- Example in CALLBACK "Callback URL examples": RP's own parameter plus these one or two.
- QR flow: no callback.
- Linked notification flows: callback URL from the device-link `certificate-choice` request is used only after the linked signature completes (CALLBACK "Callback URLs in linked notification based flows").

### 3f. Are callback parameters verifiable and bindable to the originating browser? Yes, per the documented procedure.
RP backend steps (CALLBACK Web2App steps 1-8):
1. Set a browser session cookie with `SameSite=Lax` when the flow starts.
2. Put a random query value in `initialCallbackUrl`, store it server-side tied to that browser session, and store the digest of `sessionSecret`.
3. On callback verify: session cookie matches the random value in the URL; digest of `sessionSecret` equals `sessionSecretDigest`; for authentication, SHA-256 of `userChallengeVerifier` equals `signature.userChallenge`; full response verification (section 4 below).
4. Invalidate the session cookie and the used callback URL; reuse must be rejected ("failing to invalidate may leave the user open to phishing").
5. Fail the attempt if any check fails.
Binding mechanism is therefore the RP's own cookie + random URL value; the Smart-ID-added parameters bind the callback to the Smart-ID session (secret/challenge knowledge), not to a browser. The docs claim this gives complete phishing resistance for Web2App and App2App (CALLBACK "Phishing resistance").
Known failure mode: callback opens in a different browser than the one that started the flow (embedded in-app browser, non-default browser on iOS, private mode), cookie is missing and verification must fail; guidance is to retry from the default browser (CALLBACK "Multiple browser challenges"; UX "Web2app callback exceptions"; CHANGES 3.2.6). UX also suggests closing the old tab, since the callback opens a new one.
Cookie `Secure`/`HttpOnly` and a trusted-browser `trackingID` cookie are recommended in ADDITIONAL-SECURITY (`rp-api/additional_security_measures.html`, "Keeping track of trusted and unknown browsers", pin smartid-rp-api-v3-additional-security-measures). User-Agent is explicitly called not secure for identifying browsers.
Whether the Smart-ID server rejects a callback replay itself: NOT FOUND in pinned docs (all replay prevention described is RP-side).

---

## 4. Response verification and user identity (RESP-VER `#_response_verification_steps`)

Applies to authentication and signature sessions. Steps in the documented order:
1. Web2App/App2App only: check `sessionSecretDigest` from callback against own digest.
2. `state` is exactly `COMPLETE`; `result.endResult` exactly `OK`; `signatureProtocol` is `ACSP_V2` (auth) or `RAW_DIGEST_SIGNATURE` (sign); `cert`, `signature`, `result` present.
3. Web2App/App2App authentication only: `userChallengeVerifier` check against `signature.userChallenge`.
4. Certificate chain: parse `cert.value` (DER, Base64, end-entity only); RP holds roots and intermediates locally (links to skidsolutions.eu certificate pages); trust anchors only the explicitly configured CAs (do not fall back to system store); verify issuer signatures, validity period, revocation by OCSP (via AIA) with CRL fallback (not for self-signed roots), CA basic constraints.
5. Smart-ID scheme check: certificate must carry all Smart-ID policy OIDs SK designates (list lives on skidsolutions.eu pages, not in the pinned docs: exact OIDs NOT FOUND in pinned docs).
6. Purpose: for authentication `digitalSignature` plus the Smart-ID authentication EKU `1.3.6.1.4.1.62306.5.7.0` (certificates issued from April 2025), or the older profile with `digitalSignature`, `keyEncipherment`, `dataEncipherment` plus `id-kp-clientAuth`; for signing `nonRepudiation`.
7. Assurance level: `cert.certificateLevel` (`ADVANCED` < `QUALIFIED`) must meet RP's minimum; qualified certificates must carry the profile's extensions.
8. **Identity match**: read the national identity code from the certificate Subject `serialNumber` (OID 2.5.4.5), e.g. `PNOEE-30001010004`; if the RP started the session for a known user, it must equal the expected identity.
9. Signature: for authentication rebuild `smart-id|ACSP_V2|serverRandom|rpChallenge|userChallenge|BASE64(relyingPartyName)|BASE64(brokeredRpName)|BASE64(SHA-256(interactions))|interactionTypeUsed|initialCallbackUrl|flowType` (empty fields stay as empty between separators), UTF-8, verify `signature.value` with the end-entity public key using `signature.signatureAlgorithm` and `signatureAlgorithmParameters` (RSASSA-PSS recommended; PKCS#1 v1.5 deprecated, SIGPROTO and YAML `SignatureAlgorithm`). `interactions` must be the exact Base64 string used at session creation (store it; do not re-serialize). For signing verify against the data to be signed.
10. Authentication only, after steps 1-9 pass: discard the pre-auth session id (cookie/token), issue a fresh one, and bind identity and assurance level to it server-side.
11. Let the user see their operation history / signed documents ("Allowing users to verify operations", ADDITIONAL-SECURITY).

Identity-bearing fields for mismatch rules (notification mode, where the RP asked for a specific person):
- `cert.value` Subject `serialNumber` = national identity code (step 8). Other Subject attributes (name fields): NOT FOUND in pinned docs (certificate profiles live on skidsolutions.eu).
- `result.documentNumber` (e.g. `PNOEE-30001010004-BVFM-Q` in the YAML example) identifies the specific Smart-ID account/document; usable to address the same device in later requests; mandatory when `OK`.
- `signature.flowType` (`QR`, `App2App`, `Web2App`, `Notification`): RP must verify that the returned value was one of the options it offered the user (YAML `FlowType` description). This is how a notification session is told apart from a device-link session.
- Request side: notification authentication endpoints are `.../authentication/notification/etsi/{PNOEE-...-style semantics id}` and `.../notification/document/{document-number}` (OVERVIEW). Anonymous device-link authentication exists, so identity there comes only from the certificate. No separate "user id" JSON field in the session status beyond the above: NOT FOUND in pinned docs.
- Doc caution: national identity numbers may be enumerable; prefer anonymous device-link flows, or ask for an additional non-public identifier if numbers are used (ADDITIONAL-SECURITY "Anonymous flows and user identifiers"). Notification-based flows are labelled "not recommended" for security in INTRO tables and YAML tag text; phishing protection there "relies on user awareness" (INTRO, Tables 1-2).

---

## 5. Session lifetime, expiry and cancellation

- Smart-ID side expiry exists: the session endpoint answers `404` with the meaning "session does not exist or has expired" (YAML `404_SessionNotFound`). Lifetime/TTL value: NOT FOUND in pinned docs.
- User-side time limit exists (`TIMEOUT` endResult) but its duration: NOT FOUND in pinned docs.
- 60 s is only the UX recommendation for refreshing the QR (UX), not stated as session lifetime.
- RP cancellation of an in-flight session: NOT FOUND in pinned docs. The YAML defines 14 operations total (13 POST creation endpoints for authentication, signature, certificate and certificate-choice sessions, plus `GET /v3/session/{sessionID}`); none is a cancel/delete.
- RP-session guidance after success: invalidate pre-auth cookie and used callback URL; create new authenticated session id (RESP-VER step 10, CALLBACK).
