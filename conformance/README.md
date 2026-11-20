# EUDI Wallet verifier conformance cases

Each `cases/*.yaml` file is one test: what the simulated wallet does
(`mutation`), whether a correct verifier must accept or reject it
(`expect`), and the specification section that requires it. Spec versions
are pinned in [ADR 0006](../docs/adr/0006-eudi-openid4vp.md); a new spec
version gets a new case directory.

Run against the bridge (it starts one with the harness's PID provider
trusted):

    go run ./cmd/eudi-conformance -bridge-bin <path to eidbridge> -junit out/junit.xml -md out/report.md

Results are not a certification of any kind.
