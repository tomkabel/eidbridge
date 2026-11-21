# Mutation testing: internal/mobileid (2026-11-20)

Tool: gremlins (default mutators), `gremlins unleash ./internal/mobileid`.

| Run | Killed | Lived | Not covered | Efficacy |
|---|---|---|---|---|
| First | 86 | 14 | 61 | 86.00 % |
| After `mutation_test.go` | 100 | 1 | 60 | 99.01 % |

Not covered: 52 in `mobileidtest` (test fixture, not verification code) and 8 in `client.go` lines 265–282 (HTTP status mapping and transport-error retryability). Gremlins' coverage pass does not count these `switch` case expressions as covered, so it does not mutate them. Each was mutated by hand (negation, and both boundary directions for `>= 500`); every mutant failed `go test ./internal/mobileid` after `TestTransportErrorRetryable` was added.

Surviving mutant, justified: `client.go:260` negates `if err != nil` after `http.NewRequestWithContext`. The request URL is the configured base URL (validated in `NewClient`) plus a fixed path or a session id matched against a UUID pattern, and the method is a constant, so the call cannot fail; the mutant is equivalent.
