<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Signing API (digest relay)

The signing API lets a relying party (RP) ask a person to sign a hash with their Smart-ID signing key, through the bridge. It is separate from login: different endpoints, HTTP Basic client authentication, no OIDC tokens.

## What it does and does not do

- **Digest relay.** You compute the hash of the data to be signed and send only that hash. The bridge never sees the document, the container or the data-to-be-signed.
- **Certificate step first.** You first obtain the signer's signing certificate through the bridge, because the data-to-be-signed (for example an XAdES `SignedInfo`) usually embeds that certificate and must be built before it can be hashed.
- **It verifies what it returns.** Before it hands you a signature value, the bridge verifies it against the chosen signing certificate: certificate chain, the nonRepudiation key usage, the certificate level and certificate status.
- **It makes no qualified-signature or legal-validity claim.** A verified signature value is not a qualified electronic signature and not a legally valid signature. The bridge is an unofficial, self-hosted project. Whether the result has legal effect depends on the signature format, the certificate and its trust status, timestamps, long-term validation material, and the law of your jurisdiction.
- **The integrator owns the rest.** Container building, signature format and level, timestamps (XAdES-T) and long-term validation material (LT/LTA), archival, validation and legal acceptance are your responsibility. An external qualified trust service provider (QTSP) signing or validation service is an alternative if you need a recognised service level.
- **Notification-based signing only.** The person gets a push notification with a verification code. Device-link signing (QR / same-device) is not implemented.

## Enabling

```
EIDBRIDGE_METHODS=smartid
EIDBRIDGE_SIGNING_ENABLED=true
EIDBRIDGE_CLIENTS_FILE=/path/to/clients.json
```

`EIDBRIDGE_SIGNING_CA_DIR` selects the signing-certificate CAs; when empty the bridge uses `EIDBRIDGE_SMARTID_AUTH_CA_DIR`. See [configuration](configuration.md).

## Client registration

Each signing client is an entry in the clients file with `signing_allowed` set, `client_secret_basic` authentication and a secret of at least 32 characters. The usual client fields (`redirect_uris`, `sub_mode`, and so on) are still required.

```json
[{"client_id":"signer",
  "client_secret":"<at least 32 characters, from your secret store>",
  "token_endpoint_auth_method":"client_secret_basic",
  "redirect_uris":["https://rp.example/cb"],
  "sub_mode":"pairwise",
  "signing_allowed":true}]
```

A client without `signing_allowed` gets 401 on every signing call. Keep the secret out of source control and pass it to tools through the environment.

## The contract

All calls use HTTP Basic authentication with the client ID and secret. Bodies are JSON; unknown fields are rejected; bodies over 16 KiB are rejected. Responses are sent with `Cache-Control: no-store`. Jobs are held in memory only, belong to the client that created them, and expire after 5 minutes by default.

### 1. Get the signing certificate

`POST /api/v1/sign/certificate`

```json
{"signer":"PNOEE-40404040009"}
```

`signer` is an ETSI semantics identifier. The reply is `202 {"id":"…","status":"pending"}`. Poll `GET /api/v1/sign/{id}` until:

```json
{"status":"complete","certificate":"<base64 DER>","certificate_level":"QUALIFIED"}
```

or `{"status":"failed","error":"<reason>"}`. The certificate job ID is **single use**: it is consumed by the next signature request.

### 2. Sign the digest

`POST /api/v1/sign`

```json
{"certificate":"<certificate job id>",
 "digest":"<base64 of the hash of the data to be signed>",
 "hash_algorithm":"SHA-256",
 "signature_algorithm":"rsassa-pss",
 "display_text":"Sign contract.pdf"}
```

- `hash_algorithm`: `SHA-256`, `SHA-384` or `SHA-512`; the digest length must match.
- `signature_algorithm`: `rsassa-pss`, or `sha256WithRSAEncryption`, `sha384WithRSAEncryption`, `sha512WithRSAEncryption` with the matching hash.
- `display_text`: shown on the phone, 1 to 200 characters.
- RSASSA-PSS uses MGF1 with the same hash and a salt length equal to the hash length.

The reply is `202 {"id":"…","status":"pending","verification_code":"NNNN"}`. Show the verification code to the signer. Poll `GET /api/v1/sign/{id}` until:

```json
{"status":"complete","signature":"<base64>","signature_algorithm":"…","hash_algorithm":"…",
 "certificate":"<base64 DER>","certificate_level":"…"}
```

The signature result is returned **once**; a second GET returns 404. Store it when you receive it.

## Errors

| Status | Meaning |
|---|---|
| 400 | Malformed JSON, unknown field, invalid signer, bad digest length, unsupported algorithm, empty or over-long display text. |
| 401 | Missing or wrong credentials, or the client lacks `signing_allowed`. |
| 404 | Unknown job ID, a job of another client, a certificate ID already used, or an expired or already delivered job. |
| 409 | `certificate_not_ready`: the certificate job is still pending (or the signature request came before it completed). |
| 429 | Per-client rate limit on job starts (30 per minute by default). |
| 502 | The Smart-ID service refused or failed the request to start a session. |
| 503 | The bridge is at its job capacity. |

A job that fails later reports `{"status":"failed","error":"<reason>"}` with reasons such as `refused`, `expired`, `wrong_code`, `account_unusable`, `upstream_error`, `verification_failed`, `identity_mismatch`.

## Security notes

- **Show the verification code** to the person at the moment of signing, and tell them to compare it with the phone. It is the person's check that the request on the phone is the one you started.
- Make `display_text` say what is being signed. The person approves the text, not the digest.
- Keep the client secret in a secret store or an environment variable. Use HTTPS between your service and the bridge in any real deployment.
- Do not log the signer identifier, digests or signatures.
- Notification-based signing is implemented. Device-link signing is not.
- Hashes you send identify the data only to someone who already has the data; the bridge still receives the signer's identity and the display text.

## Example: ASiC-E with the EU DSS library

[`examples/signing-asice`](../examples/signing-asice) is a Java 17 Maven CLI that acts as the integrator:

1. `sign` gets the certificate (step 1), builds an ASiC-E container with XAdES-BASELINE-B using the EU DSS library (`eu.europa.ec.joinup.sd-dss` 6.5.1) with **external signing**: `getDataToSign`, the SHA-256 digest of the bytes to be signed, step 2 through the bridge (RSASSA-PSS, DSS `RSA_SSA_PSS_SHA256_MGF1`), then `signDocument` with the returned value. The chain is the leaf plus the intermediate from `--ca`. The certificate verifier has no AIA, OCSP or CRL source, so nothing is fetched. The verification code is printed to stderr.
2. `validate` runs the DSS `SignedDocumentValidator` with the synthetic root as the only trust anchor and prints indication and sub-indication per signature.
3. `check_container.py` checks the container with the Python standard library, plus `lxml` and `cryptography` for the signature check.
4. `tamper.py` flips one bit of the signed document inside the container.
5. `run.sh` does all of it against the offline mock (`eidbridge-mock` on 127.0.0.1:18590, bridge on 127.0.0.1:18591) and stops the processes.

DSS is LGPL-2.1 and is used only as an unmodified Maven dependency; no DSS code is copied. The example files are MIT OR Apache-2.0.

Pitfall found while building it: in DSS 6.5.1 `setSigningCertificate` resets the encryption algorithm from the key (RSA), so `setEncryptionAlgorithm(RSASSA_PSS)` must be called **after** it. Otherwise the XAdES declares PKCS#1 v1.5 (`rsa-sha256`) while the signature is PSS, and validation fails with `SIG_CRYPTO_FAILURE`. This was observed.

### Limits of the example validation

- **`validate` is not an independent validator.** It uses the same library (DSS) that built the container, so a shared misreading of a standard would pass on both sides. No independent, non-DSS full XAdES/ASiC validator was run.
- `check_container.py` is a second implementation of only these pieces: ZIP layout and `mimetype`, the document and SignedProperties reference digests, and the RSASSA-PSS signature value over the canonical `SignedInfo`. It does not check the certificate chain, validity, key usage, policy or signed-property semantics.
- With the DSS default policy the result is INDETERMINATE (no revocation data), because the mock publishes no OCSP or CRL. `validate --no-revocation true` loads the same default policy and sets only the revocation-availability checks to IGNORE. That relaxation is for the mock only.
- The mock certificate is synthetic. Nothing here is a qualified signature or has legal effect.

### Results observed on 2026-11-20

Run with `examples/signing-asice/run.sh` (Go 1.24.7, OpenJDK 21 with `--release 17`, Maven 3.9.11, DSS 6.5.1, Python 3.13 with lxml 6.1.3 and cryptography 50.0.1). Identity `PNOEE-40404040009`, mock upstream. The Java runtime in that environment also printed `Picked up JAVA_TOOL_OPTIONS` lines, omitted below.

Signed container, DSS validation with revocation checks off:

```
signature S-2539…AEB3D: indication=TOTAL_PASSED subIndication=null format=XAdES-BASELINE-B
  warning: The authority info access is not present!
```

Same container, DSS default policy:

```
signature S-2539…AEB3D: indication=INDETERMINATE subIndication=CERTIFICATE_CHAIN_GENERAL_FAILURE format=XAdES-BASELINE-B
  error: The certificate validation is not conclusive!
  error: No revocation data found for the certificate!
```

Structural check without DSS (`check_container.py`): `mimetype` first and stored, content `application/vnd.etsi.asic-e+zip`, `META-INF/manifest.xml` and `META-INF/signatures001.xml` present, the data-object digest and the SignedProperties digest match, and the RSASSA-PSS signature value verifies over the canonical SignedInfo (SHA-256, salt 32, signature method `http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1`). Result: all checks passed.

After `tamper.py` flipped one bit of `sample.txt` inside the container:

```
signature S-2539…AEB3D: indication=TOTAL_FAILED subIndication=HASH_FAILURE format=XAdES-BASELINE-B
  error: The reference data object is not intact!
FAIL data object sample.txt digest differs: recomputed 1808d70d…, in XAdES f4cbf1e6…
RESULT: 1 check(s) failed
```

Both checks rejected the tampered container. The signature value itself still verified in `check_container.py`, as expected, because only the document changed.
