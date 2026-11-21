package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"strings"
	"testing"
)

func keys(t *testing.T) (*Key, *Key) {
	r, _ := rsa.GenerateKey(rand.Reader, 2048)
	e, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return &Key{KID: "r", Alg: RS256, Private: r}, &Key{KID: "e", Alg: ES256, Private: e}
}

func TestSignVerifyRoundTripAndAllowList(t *testing.T) {
	rk, ek := keys(t)
	for _, k := range []*Key{rk, ek} {
		tok, err := Sign(k, "JWT", map[string]any{"sub": "x"})
		if err != nil {
			t.Fatal(err)
		}
		_, p, err := Verify(tok, []string{RS256, ES256}, func(alg, kid string) []crypto.PublicKey { return []crypto.PublicKey{k.Public()} })
		if err != nil || !strings.Contains(string(p), `"sub":"x"`) {
			t.Fatalf("%s: %v", k.Alg, err)
		}
		if _, _, err := Verify(tok, []string{"PS256"}, func(string, string) []crypto.PublicKey { return []crypto.PublicKey{k.Public()} }); err == nil {
			t.Fatal("disallowed alg accepted")
		}
		// Tamper payload.
		parts := strings.Split(tok, ".")
		parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"y"}`))
		if _, _, err := Verify(strings.Join(parts, "."), []string{k.Alg}, func(string, string) []crypto.PublicKey { return []crypto.PublicKey{k.Public()} }); err == nil {
			t.Fatal("tampered payload accepted")
		}
	}
}

func TestNoneAndHMACAndConfusionRejected(t *testing.T) {
	rk, ek := keys(t)
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	p := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	if _, _, err := Verify(h+"."+p+".", []string{RS256, ES256}, func(string, string) []crypto.PublicKey { return []crypto.PublicKey{rk.Public()} }); err == nil {
		t.Fatal("none accepted")
	}
	// ES256 header with an RSA key must not verify (key/alg pairing).
	tok, _ := Sign(ek, "", map[string]any{})
	if _, _, err := Verify(tok, []string{ES256}, func(string, string) []crypto.PublicKey { return []crypto.PublicKey{rk.Public()} }); err == nil {
		t.Fatal("alg/key confusion accepted")
	}
	crit := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","crit":["x"]}`))
	if _, _, err := Verify(crit+"."+p+".AA", []string{RS256}, func(string, string) []crypto.PublicKey { return nil }); err == nil {
		t.Fatal("crit accepted")
	}
	for _, bad := range []string{"", "a.b", "a.b.c.d", "!.!.!", strings.Repeat("a", MaxJWS+1)} {
		if _, _, err := Verify(bad, []string{RS256}, func(string, string) []crypto.PublicKey { return nil }); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestKeyChecks(t *testing.T) {
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if CheckKey(RS256, small.Public()) == nil || CheckKey(ES256, p384.Public()) == nil || CheckKey("HS256", small.Public()) == nil {
		t.Fatal("weak or wrong key accepted")
	}
	if _, err := Sign(&Key{Alg: RS256, Private: small}, "", nil); err == nil {
		t.Fatal("signed with small key")
	}
}

func TestJWKRoundTripAndThumbprint(t *testing.T) {
	rk, ek := keys(t)
	for _, k := range []*Key{rk, ek} {
		j, err := PublicJWK(k.Public(), "kid", k.Alg)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := j.Key()
		if err != nil {
			t.Fatal(err)
		}
		a, _ := Thumbprint(pub)
		b, _ := Thumbprint(k.Public())
		if a != b || len(a) != 43 {
			t.Fatal("thumbprint mismatch")
		}
	}
	// RFC 7638 §3.1 example key thumbprint.
	j := JWK{Kty: "RSA", E: "AQAB", N: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}
	pub, err := j.Key()
	if err != nil {
		t.Fatal(err)
	}
	if tp, _ := Thumbprint(pub); tp != "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
		t.Fatalf("RFC 7638 vector: %s", tp)
	}
	for _, bad := range []JWK{{Kty: "oct"}, {Kty: "EC", Crv: "P-384"}, {Kty: "EC", Crv: "P-256", X: "AA", Y: "AA"}, {Kty: "RSA", N: "AQAB", E: "AQAB"}} {
		if _, err := bad.Key(); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}

func FuzzVerify(f *testing.F) {
	rk, _ := keys(&testing.T{})
	tok, _ := Sign(rk, "JWT", map[string]any{"a": 1})
	f.Add(tok)
	f.Add("eyJhbGciOiJub25lIn0.e30.")
	f.Fuzz(func(t *testing.T, s string) {
		Verify(s, []string{RS256, ES256}, func(string, string) []crypto.PublicKey { return []crypto.PublicKey{rk.Public()} })
	})
}
