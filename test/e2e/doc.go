// Package e2e holds end-to-end tests that put the eidbridge binary behind real
// identity providers (Keycloak, authentik, Zitadel, Ory) running in Docker.
// The tests carry the build tag e2e:
//
//	GOTOOLCHAIN=local go test -tags e2e -count=1 -v ./test/e2e/...
package e2e
