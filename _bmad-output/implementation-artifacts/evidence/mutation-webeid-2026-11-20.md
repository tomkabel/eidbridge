# Mutation testing: internal/webeid (2026-11-20)

Tool: gremlins (default mutators), `gremlins unleash ./internal/webeid`.

| Run | Killed | Lived | Efficacy |
|---|---|---|---|
| First | 77 | 13 | 85.56 % |
| After `mutation_test.go` | 90 | 1 | 98.90 % |

Not covered mutants are in `webeidtest` (test fixture).

Surviving mutant, justified: `validate.go:57` changes `c > 127` to `c >= 127` in the ASCII-host check of the configured origin. The only character that separates the two is DEL (0x7f), which `url.Parse` already rejects in a host, so the mutant is equivalent; `TestASCIIOriginControlCharacter` documents this and fails if `url.Parse` ever starts accepting DEL.
