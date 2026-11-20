package smartid

import "testing"

func liveStatus(t *testing.T) StatusChecker {
	t.Helper()
	return NoStatusCheck{Reason: "live test before OCSP"}
}
