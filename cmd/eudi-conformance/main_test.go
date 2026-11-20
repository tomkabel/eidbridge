package main

import (
	"os/exec"
	"path/filepath"
	"testing"
)

// The catalog parses strictly and has one positive and at least ten
// negative cases, each with a specification link (Story 6.2 AC).
func TestCatalog(t *testing.T) {
	cs, err := loadCases(filepath.Join("..", "..", "conformance", "cases"))
	if err != nil {
		t.Fatal(err)
	}
	pos, neg := 0, 0
	for _, c := range cs {
		if c.Expect == "accept" {
			pos++
		} else {
			neg++
		}
		for _, s := range c.Spec {
			if s.URL == "" || s.Section == "" {
				t.Errorf("%s: spec reference incomplete", c.ID)
			}
		}
	}
	if pos < 1 || neg < 10 {
		t.Fatalf("%d positive, %d negative", pos, neg)
	}
}

// Runs every case against a freshly built bridge.
func TestHarnessAgainstBridge(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and starts the bridge")
	}
	bin := filepath.Join(t.TempDir(), "eidbridge")
	if out, err := exec.Command("go", "build", "-o", bin, "../eidbridge").CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	cs, err := loadCases(filepath.Join("..", "..", "conformance", "cases"))
	if err != nil {
		t.Fatal(err)
	}
	h, err := newHarness(bin, filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	defer h.close()
	for _, c := range cs {
		if pass, obs := h.run(c); !pass {
			t.Errorf("%s (expect %s): %s", c.ID, c.Expect, obs)
		}
	}
}
