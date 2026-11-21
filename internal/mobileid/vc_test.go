package mobileid

import (
	"encoding/hex"
	"testing"
)

// MID REST API §2.4.1 worked example: hash 2f665f6a…8cb6 gives 1462.
func TestVerificationCodeSpecExample(t *testing.T) {
	h, _ := hex.DecodeString("2f665f6a6999e0ef0752e00ec9f453adf59d8cb6")
	if got := VerificationCode(h); got != "1462" {
		t.Fatalf("got %s", got)
	}
}

func TestVerificationCodeBounds(t *testing.T) {
	zero := make([]byte, 32)
	if got := VerificationCode(zero); got != "0000" {
		t.Fatalf("zero hash: %s", got)
	}
	ones := make([]byte, 32)
	for i := range ones {
		ones[i] = 0xff
	}
	if got := VerificationCode(ones); got != "8191" {
		t.Fatalf("all-ones hash: %s", got)
	}
	// leading zero padding: top 6 bits 000000, low 7 bits 0101001 = 41
	h := make([]byte, 32)
	h[31] = 0x29
	if got := VerificationCode(h); got != "0041" {
		t.Fatalf("padding: %s", got)
	}
}
