package version

import "testing"

func TestStringMarksUnofficial(t *testing.T) {
	if got := String(); got != "eidbridge dev (unofficial)" {
		t.Fatalf("String() = %q", got)
	}
}
