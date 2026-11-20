package logx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func capture(t *testing.T) (*slog.Logger, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	return New(&buf, slog.LevelDebug), &buf
}

// Synthetic and published demo test identifiers only.
var leakCases = []struct {
	name, in, secret string
}{
	{"etsi EE semantics id", "user PNOEE-40404040009 started", "40404040009"},
	{"etsi LV semantics id", "PNOLV-040404-10003 refused", "040404-10003"},
	{"etsi passport", "PASKZ-987654321012", "987654321012"},
	{"etsi id card", "IDCCZ-1234567890", "1234567890"},
	{"document number", "doc PNOEE-40404040009-MOCK-Q ok", "40404040009-MOCK-Q"},
	{"bare EE code", "code 39901012239 here", "39901012239"},
	{"bare LT code", "lt=61101019999", "61101019999"},
	{"LV code with dash", "lv 311299-19993", "311299-19993"},
	{"LV code no dash", "lv 31129919993", "31129919993"},
	{"phone e164", "phone +37200000766", "37200000766"},
	{"pem", "cert -----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUQ0FGRSBCQUJF\n-----END CERTIFICATE----- end", "MIIBszCCAVmgAwIBAgIUQ0FGRSBCQUJF"},
	{"long base64", "sig=Vak2Q0NiFnh6+lW+YaJuB8yMYM7k3I5QfsUxS3Y1Ddm3qy6HvebLl0/t17dq289/+4mGx45qnHVNj1Cz", "Vak2Q0NiFnh6"},
	{"base64url token", "code xK3n0aaJ9zq8RTvW1y2b-c_dFgHiJkLmNoPqRsTuVwXy", "xK3n0aaJ9zq8RTvW1y2b"},
	{"jwt", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJQTk9FRS00MDQwNDA0MDAwOSJ9.c2lnbmF0dXJlc2lnbmF0dXJlc2lnbmF0dXJl", "eyJzdWIiOiJQTk9FRS00MDQwNDA0MDAwOSJ9"},
}

func TestRedactsIdentifierFormatsInMessages(t *testing.T) {
	for _, tc := range leakCases {
		t.Run(tc.name, func(t *testing.T) {
			l, buf := capture(t)
			l.Debug(tc.in)
			if strings.Contains(buf.String(), tc.secret) {
				t.Fatalf("message leaked %q: %s", tc.secret, buf)
			}
		})
	}
}

func TestRedactsIdentifierFormatsInAttrValues(t *testing.T) {
	for _, tc := range leakCases {
		t.Run(tc.name, func(t *testing.T) {
			l, buf := capture(t)
			l.Info("event", "detail", tc.in)
			if strings.Contains(buf.String(), tc.secret) {
				t.Fatalf("attr leaked %q: %s", tc.secret, buf)
			}
		})
	}
}

func TestSensitiveKeysAlwaysRedacted(t *testing.T) {
	keys := []string{"sessionSecret", "session_secret", "signature", "cert", "certificate", "id_token", "access_token",
		"code", "code_verifier", "personalCode", "IDCode", "documentNumber", "rpChallenge", "userChallengeVerifier",
		"sessionSecretDigest", "sessionToken", "password", "client_secret", "Authorization", "cookie", "given_name",
		"family_name", "phone", "token", "vp_token", "nonce", "state", "digest"}
	for _, k := range keys {
		l, buf := capture(t)
		l.Info("x", k, "short")
		if strings.Contains(buf.String(), "short") {
			t.Errorf("key %q value not redacted: %s", k, buf)
		}
	}
}

func TestNestedGroupsAndWithAttrsRedacted(t *testing.T) {
	l, buf := capture(t)
	l = l.With("signature", "abc").WithGroup("flow").With("person", "PNOEE-40404040009")
	l.Info("x", slog.Group("inner", "cert", "zzz", "note", "code 39901012239"))
	out := buf.String()
	for _, s := range []string{"abc", "40404040009", "zzz", "39901012239"} {
		if strings.Contains(out, s) {
			t.Fatalf("leaked %q: %s", s, out)
		}
	}
}

func TestWrappedErrorsRedacted(t *testing.T) {
	l, buf := capture(t)
	inner := errors.New("upstream refused PNOEE-40404040009")
	l.Error("failed", "err", fmt.Errorf("verify: %w", inner))
	if strings.Contains(buf.String(), "40404040009") {
		t.Fatalf("error leaked: %s", buf)
	}
	if !strings.Contains(buf.String(), "verify: upstream refused") {
		t.Fatalf("error context lost: %s", buf)
	}
}

func TestPersonalAlwaysMasked(t *testing.T) {
	l, buf := capture(t)
	l.Info("x", "who", Personal("PNOEE-40404040009"))
	if strings.Contains(buf.String(), "40404040009") || !strings.Contains(buf.String(), "[personal]") {
		t.Fatalf("Personal not masked: %s", buf)
	}
}

func TestBytesAndArbitraryValuesDropped(t *testing.T) {
	type identity struct{ GivenName, Code string }
	l, buf := capture(t)
	l.Info("x", "raw", []byte("secretbytes"), "id", identity{"MARY ÄNN", "40404040009"}, "ptr", &identity{"MARY", "1"})
	out := buf.String()
	for _, s := range []string{"secretbytes", "MARY", "40404040009"} {
		if strings.Contains(out, s) {
			t.Fatalf("leaked %q: %s", s, out)
		}
	}
}

func TestSafeValuesKept(t *testing.T) {
	l, buf := capture(t)
	l.Info("flow verified", "method", "smartid", "state", nil, "route", "/flow/{id}/status", "status", 200, "ok", true)
	out := buf.String()
	for _, s := range []string{"flow verified", "smartid", "/flow/{id}/status", "200", "true"} {
		if !strings.Contains(out, s) {
			t.Fatalf("lost safe value %q: %s", s, out)
		}
	}
}

func TestDebugLevelGetsSameRedaction(t *testing.T) {
	var buf bytes.Buffer
	h := NewHandler(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.New(h).Debug("PNOEE-40404040009", "cert", "x")
	if strings.Contains(buf.String(), "40404040009") || strings.Contains(buf.String(), "cert=x") {
		t.Fatalf("debug leaked: %s", buf.String())
	}
}

func TestHandlerEnabledDelegates(t *testing.T) {
	h := NewHandler(slog.NewTextHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelWarn}))
	if h.Enabled(context.Background(), slog.LevelInfo) {
		t.Fatal("info should be disabled")
	}
}

func TestRedactStringIdempotentAndBounded(t *testing.T) {
	s := Redact("PNOEE-40404040009 and 39901012239")
	if Redact(s) != s {
		t.Fatalf("not idempotent: %q -> %q", s, Redact(s))
	}
}

func FuzzRedactNeverLeaksDigitsRuns(f *testing.F) {
	for _, tc := range leakCases {
		f.Add(tc.in)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := Redact(s)
		// No 11-digit run starting 1-6 survives redaction.
		if reBareEE.MatchString(out) {
			t.Fatalf("11-digit code survived: %q -> %q", s, out)
		}
		if strings.Contains(out, "-----BEGIN") && strings.Contains(out, "-----END") && rePEM.MatchString(out) {
			t.Fatalf("pem survived: %q", out)
		}
	})
}
