package mobileid

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
	"github.com/tomkabel/eidbridge/internal/smartid"
)

func loadCapture(t *testing.T, name string) (capture, *Session, *Status) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "live", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var c capture
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	h, _ := base64.StdEncoding.DecodeString(c.Hash)
	country, err := ValidateInput(c.Phone, c.Code)
	if err != nil {
		t.Fatal(err)
	}
	st, err := ParseStatus(c.Status)
	if err != nil {
		t.Fatal(err)
	}
	return c, &Session{ID: "x", Hash: h, VC: VerificationCode(h), Country: country, Code: c.Code, Phone: c.Phone, hashType: "SHA256"}, st
}

func replayClient(t *testing.T, c capture) *Client {
	at, _ := time.Parse(time.RFC3339, c.Captured)
	cl := liveClient(t, smartid.NoStatusCheck{})
	cl.cfg.Now = func() time.Time { return at }
	return cl
}

// Known-answer tests on real demo responses captured 2026-11-20 (Story 4.2:
// recorded fixtures with tampered signature and identity mismatch).
func TestReplayLiveOK(t *testing.T) {
	c, s, st := loadCapture(t, "ok")
	id, err := replayClient(t, c).Verify(context.Background(), s, st)
	if err != nil || id.Code != "51307149560" || id.Country != "EE" || id.GivenName != "MARY ÄNN" {
		t.Fatalf("%+v %v", id, err)
	}
}

func TestReplayLiveTamperedSignature(t *testing.T) {
	c, s, st := loadCapture(t, "ok")
	b, _ := base64.StdEncoding.DecodeString(st.Signature.Value)
	b[len(b)-1] ^= 1
	st.Signature.Value = base64.StdEncoding.EncodeToString(b)
	if _, err := replayClient(t, c).Verify(context.Background(), s, st); authn.ReasonOf(err) != authn.ReasonVerificationFailed {
		t.Fatalf("tampered signature: %v", err)
	}
}

func TestReplayLiveOtherHash(t *testing.T) {
	c, s, st := loadCapture(t, "ok")
	s.Hash[0] ^= 1 // the response signs a hash this session did not send
	if _, err := replayClient(t, c).Verify(context.Background(), s, st); authn.ReasonOf(err) != authn.ReasonVerificationFailed {
		t.Fatalf("other hash: %v", err)
	}
}

func TestReplayLiveIdentityMismatch(t *testing.T) {
	c, s, st := loadCapture(t, "ok")
	s.Code = "60001017869" // the person the user typed differs from the certificate
	if _, err := replayClient(t, c).Verify(context.Background(), s, st); authn.ReasonOf(err) != authn.ReasonIdentityMismatch {
		t.Fatalf("identity mismatch: %v", err)
	}
}

func TestReplayLiveCertExpiredAtVerificationTime(t *testing.T) {
	c, s, st := loadCapture(t, "ok")
	cl := replayClient(t, c)
	cl.cfg.Now = func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) }
	if _, err := cl.Verify(context.Background(), s, st); authn.ReasonOf(err) != authn.ReasonVerificationFailed {
		t.Fatalf("expired: %v", err)
	}
}

func TestReplayLiveEndResults(t *testing.T) {
	for name, reason := range map[string]string{"user-cancelled": authn.ReasonRefused, "not-mid-client": authn.ReasonAccountUnusable,
		"delivery-error": authn.ReasonUpstreamError, "signature-hash-mismatch": authn.ReasonAccountUnusable} {
		c, s, st := loadCapture(t, name)
		if _, err := replayClient(t, c).Verify(context.Background(), s, st); authn.ReasonOf(err) != reason {
			t.Errorf("%s: %v", name, err)
		}
	}
}
