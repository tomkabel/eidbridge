# OIDF conformance raw results (2026-11-20)

Summary and pins: [docs/conformance.md](../../../docs/conformance.md). Exported result zips are kept out of the repository because they contain the run's client secret.

Config plan: `oidcc-discovery-endpoint-verification ... FINISHED - result PASSED. 47 log entries - 31 SUCCESS 0 FAILURE, 0 WARNING`

Basic plan, per module (number|module|result):

```
1|oidcc-server|FAILED
2|oidcc-response-type-missing|PASSED
3|oidcc-userinfo-get|FAILED
4|oidcc-userinfo-post-header|FAILED
5|oidcc-userinfo-post-body|FAILED
6|oidcc-ensure-request-without-nonce-succeeds-for-code-flow|FAILED
7|oidcc-scope-profile|FAILED
8|oidcc-scope-email|SKIPPED
9|oidcc-scope-address|SKIPPED
10|oidcc-scope-phone|SKIPPED
11|oidcc-scope-all|SKIPPED
12|oidcc-alternate-happy-flow|SKIPPED
13|oidcc-display-page|FAILED
14|oidcc-display-popup|FAILED
15|oidcc-prompt-login|FAILED
16|oidcc-prompt-none-not-logged-in|FAILED
17|oidcc-prompt-none-logged-in|FAILED
18|oidcc-max-age-1|FAILED
19|oidcc-max-age-10000|FAILED
20|oidcc-ensure-request-with-unknown-parameter-succeeds|FAILED
21|oidcc-id-token-hint|FAILED
22|oidcc-login-hint|FAILED
23|oidcc-ui-locales|FAILED
24|oidcc-claims-locales|FAILED
25|oidcc-ensure-request-with-acr-values-succeeds|FAILED
26|oidcc-codereuse|FAILED
27|oidcc-codereuse-30seconds|FAILED
28|oidcc-ensure-registered-redirect-uri|FAILED
29|oidcc-ensure-post-request-succeeds|FAILED
30|oidcc-server-client-secret-post|FAILED
31|oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported|SKIPPED
32|oidcc-claims-essential|FAILED
33|oidcc-ensure-request-object-with-redirect-uri|FAILED
34|oidcc-refresh-token|FAILED
35|oidcc-ensure-request-with-valid-pkce-succeeds|PASSED
```
