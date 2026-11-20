package authn_test

import (
	"testing"

	"github.com/tomkabel/eidbridge/internal/authn"
	"github.com/tomkabel/eidbridge/internal/authn/authntest"
)

func TestRegistryContractFakeMethod(t *testing.T) {
	authntest.Run(t, authntest.FakeHarness{F: &authntest.Fake{}})
	r, err := authn.NewRegistry(&authntest.Fake{MethodName: "a"}, &authntest.Fake{MethodName: "b"})
	if err != nil || r.Len() != 2 || r.Names()[0] != "a" {
		t.Fatalf("registry: %v %v", r, err)
	}
	if _, ok := r.Get("b"); !ok {
		t.Fatal("get b")
	}
	if _, err := authn.NewRegistry(&authntest.Fake{MethodName: "a"}, &authntest.Fake{MethodName: "a"}); err == nil {
		t.Fatal("duplicate accepted")
	}
	if _, err := authn.NewRegistry(); err == nil {
		t.Fatal("empty registry accepted")
	}
}

func TestReasonOf(t *testing.T) {
	if authn.ReasonOf(&authn.Error{Reason: authn.ReasonRefused}) != authn.ReasonRefused || authn.ReasonOf(nil) != authn.ReasonUpstreamError {
		t.Fatal("ReasonOf")
	}
}
