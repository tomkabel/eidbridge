# `eidbridge doctor`

Checks the configured upstreams and trust bundles once and exits. It is not part of readiness: `/readyz` never depends on upstreams (architecture ADR-009).

    eidbridge doctor [--json]      # with the same environment (and --demo) as serve

What it contacts: one `HEAD` request to each configured upstream base URL (Smart-ID, Mobile-ID). Nothing else: no status responders, no telemetry. Web eID and EUDI have no upstream to contact; only their trust bundles are checked.

Exit code: 0 when no result is `FAIL`, 1 otherwise, 2 on usage errors.

| Check | OK | WARN | FAIL |
|---|---|---|---|
| Upstream | TLS handshake and pin match | server certificate expires in under 30 days, or pins disabled | connection, chain or hostname error, or pin mismatch |
| Trust bundle | every CA valid for 30+ days | a CA expires in under 30 days | a CA has expired, or the bundle is empty |

## JSON schema (`--json`, version 1)

```json
{
  "version": 1,
  "results": [
    {
      "component": "smartid | mobileid | webeid | eudi",
      "kind": "upstream | trust",
      "env": "demo | production",
      "host": "host[:port]",
      "tls_version": "TLS 1.3",
      "cipher": "TLS_AES_128_GCM_SHA256",
      "pin": "ok | mismatch | disabled",
      "cert_expires_in_days": 212,
      "rtt_ms": 41,
      "certs": 2,
      "status": "OK | WARN | FAIL",
      "detail": "free text"
    }
  ]
}
```

Fields that do not apply to a result's `kind` are omitted, except `cert_expires_in_days`, which is always present (server certificate for `upstream`, earliest CA for `trust`). New fields may be added within version 1; removals or meaning changes raise the version.
