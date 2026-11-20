package smartid

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/smartid/smartidtest"
)

var testPKI = smartidtest.NewPKI("verify")

type synth struct {
	c    *Client
	s    *Session
	leaf *smartidtest.Leaf
	st   map[string]any
	cb   *Callback
}

type statusFn func(context.Context, *x509.Certificate, *x509.Certificate) error

func (f statusFn) Check(ctx context.Context, l, i *x509.Certificate) error { return f(ctx, l, i) }

// newSynth builds a fully valid synthetic signed result for flow.
func newSynth(t *testing.T, flow string, lo smartidtest.LeafOptions) *synth {
	t.Helper()
	trust := NewTrustStore(testPKI.Root, testPKI.Inter)
	c, err := NewClient(Config{BaseURL: "https://rp.invalid", RPUUID: DemoRPUUID, RPName: DemoRPName, SchemeName: SchemeDemo,
		Trust: trust, MinCertLevel: LevelQualified, Status: NoStatusCheck{}, PolicyOIDs: DemoPolicyOIDs})
	if err != nil {
		t.Fatal(err)
	}
	inter, _ := Interactions("synthetic")
	ch := make([]byte, 32)
	rand.Read(ch)
	secret := make([]byte, 18)
	rand.Read(secret)
	s := &Session{Flow: flow, Interactions: inter, Lang: "eng", token: "abcdefghijklmnopqrstuvwx", secret: secret,
		linkBase: "https://sid.demo.sk.ee/device-link", rpChallenge: ch, scheme: SchemeDemo, rpName: DemoRPName, created: time.Now()}
	if flow == FlowWeb2App {
		s.InitialCallbackURL = "https://bridge.example/flow/callback?value=xyz"
	}
	if flow == FlowNotification {
		s.ExpectedIdentity = "PNOEE-40404040009"
	}
	leaf := testPKI.NewLeaf(lo)
	sy := &synth{c: c, s: s, leaf: leaf}
	sy.sign()
	return sy
}

func (sy *synth) sign() {
	verifier := "verifier-" + base64.RawURLEncoding.EncodeToString(sy.s.rpChallenge[:8])
	uc := sha256.Sum256([]byte(verifier))
	userChallenge := base64.RawURLEncoding.EncodeToString(uc[:])
	serverRandom := base64.StdEncoding.EncodeToString(sy.s.rpChallenge[:18])
	msg := ACSPv2Payload(SchemeDemo, serverRandom, sy.s.RPChallengeB64(), userChallenge, DemoRPName, "", sy.s.Interactions,
		"displayTextAndPIN", sy.s.InitialCallbackURL, sy.s.Flow)
	var sigv []byte
	if k, ok := sy.leaf.Key.(*rsa.PrivateKey); ok {
		d := sha512.Sum512(msg)
		sigv, _ = rsa.SignPSS(rand.Reader, k, crypto.SHA512, d[:], &rsa.PSSOptions{SaltLength: 64})
	} else {
		sigv = []byte("not-rsa")
	}
	serial := subjectAttr(sy.leaf.Cert.Subject, oidSerialNumber)
	sy.st = map[string]any{"state": "COMPLETE", "result": map[string]any{"endResult": "OK", "documentNumber": serial + "-MOCK-Q"},
		"signatureProtocol": "ACSP_V2",
		"signature": map[string]any{"value": base64.StdEncoding.EncodeToString(sigv), "serverRandom": serverRandom,
			"userChallenge": userChallenge, "flowType": sy.s.Flow, "signatureAlgorithm": "rsassa-pss",
			"signatureAlgorithmParameters": map[string]any{"hashAlgorithm": "SHA-512",
				"maskGenAlgorithm": map[string]any{"algorithm": "id-mgf1", "parameters": map[string]any{"hashAlgorithm": "SHA-512"}},
				"saltLength":       64, "trailerField": "0xbc"}},
		"cert":                map[string]any{"value": base64.StdEncoding.EncodeToString(sy.leaf.Cert.Raw), "certificateLevel": "QUALIFIED"},
		"interactionTypeUsed": "displayTextAndPIN"}
	sd := sha256.Sum256(sy.s.secret)
	sy.cb = &Callback{SessionSecretDigest: base64.RawURLEncoding.EncodeToString(sd[:]), UserChallengeVerifier: verifier}
}

func (sy *synth) verify() (*Identity, error) {
	b, _ := json.Marshal(sy.st)
	st, err := ParseStatus(b)
	if err != nil {
		return nil, err
	}
	var cb *Callback
	if sy.s.Flow == FlowWeb2App {
		cb = sy.cb
	}
	return sy.c.Verify(sy.s, st, cb)
}

func (sy *synth) sig() map[string]any { return sy.st["signature"].(map[string]any) }
func (sy *synth) params() map[string]any {
	return sy.sig()["signatureAlgorithmParameters"].(map[string]any)
}

func TestSyntheticPositiveAllFlows(t *testing.T) {
	for _, f := range []string{FlowQR, FlowWeb2App, FlowNotification} {
		sy := newSynth(t, f, smartidtest.LeafOptions{})
		id, err := sy.verify()
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if id.Code != "40404040009" || id.Country != "EE" || id.GivenName != "OK" || id.Surname != "TEST" {
			t.Fatalf("%s: identity %+v", f, *id)
		}
	}
	// Old clientAuth profile is accepted.
	if _, err := newSynth(t, FlowQR, smartidtest.LeafOptions{OldProfile: true}).verify(); err != nil {
		t.Fatalf("old profile: %v", err)
	}
}

// One negative test per response-verification step in
// research/smart-id-v3-facts-2026-11-18.md §4 (steps 1–9) plus status,
// parameter and lifecycle checks. Each must fail closed.
func TestVerifyNegativePerStep(t *testing.T) {
	type tc struct {
		flow   string
		lo     smartidtest.LeafOptions
		mutate func(*synth)
		reason string
	}
	other := smartidtest.NewPKI("other")
	cases := map[string]tc{
		// Step 1
		"s1 web2app missing callback": {flow: FlowWeb2App, mutate: func(sy *synth) { sy.cb = nil; sy.s.Flow = FlowWeb2App }},
		"s1 web2app wrong digest":     {flow: FlowWeb2App, mutate: func(sy *synth) { sy.cb.SessionSecretDigest = strings.Repeat("x", 43) }},
		"s1 web2app empty digest":     {flow: FlowWeb2App, mutate: func(sy *synth) { sy.cb.SessionSecretDigest = "" }},
		// Step 2
		"s2 state running":           {mutate: func(sy *synth) { sy.st["state"] = "RUNNING" }, reason: ReasonUnknownEndResult},
		"s2 endResult refused":       {mutate: func(sy *synth) { sy.st["result"].(map[string]any)["endResult"] = "USER_REFUSED" }, reason: ReasonRefused},
		"s2 protocol raw digest":     {mutate: func(sy *synth) { sy.st["signatureProtocol"] = "RAW_DIGEST_SIGNATURE" }},
		"s2 missing cert":            {mutate: func(sy *synth) { delete(sy.st, "cert") }},
		"s2 missing signature":       {mutate: func(sy *synth) { delete(sy.st, "signature") }},
		"s2 missing documentNumber":  {mutate: func(sy *synth) { delete(sy.st["result"].(map[string]any), "documentNumber") }},
		"s2 flowType not offered":    {mutate: func(sy *synth) { sy.sig()["flowType"] = FlowNotification }},
		"s2 flowType web2app for qr": {mutate: func(sy *synth) { sy.sig()["flowType"] = FlowWeb2App }},
		"s2 malformed userChallenge": {mutate: func(sy *synth) { sy.sig()["userChallenge"] = "short" }},
		"s2 malformed serverRandom":  {mutate: func(sy *synth) { sy.sig()["serverRandom"] = "!!" }},
		"s2 interaction not offered": {mutate: func(sy *synth) { sy.st["interactionTypeUsed"] = "confirmationMessage" }},
		"s2 interaction empty":       {mutate: func(sy *synth) { sy.st["interactionTypeUsed"] = "" }},
		// Step 3
		"s3 web2app wrong verifier": {flow: FlowWeb2App, mutate: func(sy *synth) { sy.cb.UserChallengeVerifier = "nope" }},
		"s3 web2app empty verifier": {flow: FlowWeb2App, mutate: func(sy *synth) { sy.cb.UserChallengeVerifier = "" }},
		// Step 4
		"s4 cert not base64": {mutate: func(sy *synth) { sy.st["cert"].(map[string]any)["value"] = "!!!" }},
		"s4 cert garbage": {mutate: func(sy *synth) {
			sy.st["cert"].(map[string]any)["value"] = base64.StdEncoding.EncodeToString([]byte("garbage"))
		}},
		"s4 untrusted chain": {lo: smartidtest.LeafOptions{SelfIssuedBy: other}},
		"s4 expired cert":    {lo: smartidtest.LeafOptions{NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-24 * time.Hour)}},
		"s4 not yet valid":   {lo: smartidtest.LeafOptions{NotBefore: time.Now().Add(24 * time.Hour)}},
		"s4 leaf is CA":      {lo: smartidtest.LeafOptions{IsCA: true}},
		"s4 root as leaf": {mutate: func(sy *synth) {
			sy.st["cert"].(map[string]any)["value"] = base64.StdEncoding.EncodeToString(testPKI.Root.Raw)
		}},
		// Step 5
		"s5 missing policy": {lo: smartidtest.LeafOptions{NoPolicy: true}},
		// Step 6
		"s6 no auth EKU":            {lo: smartidtest.LeafOptions{NoAuthEKU: true}},
		"s6 no digitalSignature":    {lo: smartidtest.LeafOptions{KeyUsage: x509.KeyUsageKeyEncipherment}},
		"s6 old profile missing KU": {lo: smartidtest.LeafOptions{OldProfile: true, KeyUsage: x509.KeyUsageDigitalSignature}},
		// Step 7
		"s7 level advanced": {mutate: func(sy *synth) { sy.st["cert"].(map[string]any)["certificateLevel"] = "ADVANCED" }},
		"s7 level unknown":  {mutate: func(sy *synth) { sy.st["cert"].(map[string]any)["certificateLevel"] = "SUPER" }},
		"s7 level missing":  {mutate: func(sy *synth) { sy.st["cert"].(map[string]any)["certificateLevel"] = "" }},
		// Step 8
		"s8 serialNumber other form":           {lo: smartidtest.LeafOptions{SerialNumber: "XYZEE-40404040009"}},
		"s8 notification other person":         {flow: FlowNotification, lo: smartidtest.LeafOptions{SerialNumber: "PNOEE-39901012239"}, reason: ReasonIdentityMismatch},
		"s8 document of other subject":         {mutate: func(sy *synth) { sy.st["result"].(map[string]any)["documentNumber"] = "PNOEE-39901012239-MOCK-Q" }, reason: ReasonIdentityMismatch},
		"s8 notification by document mismatch": {flow: FlowNotification, mutate: func(sy *synth) { sy.s.ExpectedIdentity = "PNOEE-40404040009-ZZZZ-Q" }, reason: ReasonIdentityMismatch},
		// Step 9
		"s9 tampered signature":   {mutate: func(sy *synth) { v := []byte(sy.sig()["value"].(string)); v[10] ^= 1; sy.sig()["value"] = string(v) }},
		"s9 signature not base64": {mutate: func(sy *synth) { sy.sig()["value"] = "!!!" }},
		"s9 wrong challenge":      {mutate: func(sy *synth) { sy.s.rpChallenge[0] ^= 0xff }},
		"s9 wrong interactions":   {mutate: func(sy *synth) { sy.s.Interactions, _ = Interactions("other text") }},
		"s9 wrong rp name":        {mutate: func(sy *synth) { sy.s.rpName = "OTHER" }},
		"s9 wrong callback url":   {flow: FlowWeb2App, mutate: func(sy *synth) { sy.s.InitialCallbackURL += "x" }},
		"s9 pkcs1v15 rejected":    {mutate: func(sy *synth) { sy.sig()["signatureAlgorithm"] = "sha256WithRSAEncryption" }},
		"s9 sha3 rejected":        {mutate: func(sy *synth) { sy.params()["hashAlgorithm"] = "SHA3-512" }},
		"s9 missing params":       {mutate: func(sy *synth) { delete(sy.sig(), "signatureAlgorithmParameters") }},
		"s9 missing mgf":          {mutate: func(sy *synth) { delete(sy.params(), "maskGenAlgorithm") }},
		"s9 missing salt":         {mutate: func(sy *synth) { delete(sy.params(), "saltLength") }},
		"s9 mgf hash differs": {mutate: func(sy *synth) {
			sy.params()["maskGenAlgorithm"].(map[string]any)["parameters"] = map[string]any{"hashAlgorithm": "SHA-256"}
		}},
		"s9 mgf algorithm": {mutate: func(sy *synth) { sy.params()["maskGenAlgorithm"].(map[string]any)["algorithm"] = "other" }},
		"s9 salt length":   {mutate: func(sy *synth) { sy.params()["saltLength"] = 32 }},
		"s9 trailer field": {mutate: func(sy *synth) { sy.params()["trailerField"] = "0x01" }},
		"s9 ec key":        {lo: smartidtest.LeafOptions{ECKey: true}},
		"s9 rsa 1024":      {lo: smartidtest.LeafOptions{RSABits: 1024}},
		// Status and lifecycle
		"status unavailable": {mutate: func(sy *synth) {
			sy.c.cfg.Status = statusFn(func(context.Context, *x509.Certificate, *x509.Certificate) error { return errors.New("ocsp down") })
		}, reason: ReasonStatusUnavailable},
		"status revoked": {mutate: func(sy *synth) {
			sy.c.cfg.Status = statusFn(func(context.Context, *x509.Certificate, *x509.Certificate) error { return ErrRevoked })
		}},
		"destroyed session": {mutate: func(sy *synth) { sy.s.Destroy() }},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			flow := c.flow
			if flow == "" {
				flow = FlowQR
			}
			sy := newSynth(t, flow, c.lo)
			if c.mutate != nil {
				c.mutate(sy)
			}
			id, err := sy.verify()
			if err == nil || id != nil {
				t.Fatal("verified, want failure")
			}
			want := c.reason
			if want == "" {
				want = ReasonVerificationFailed
			}
			if got := ReasonOf(err); got != want {
				t.Fatalf("reason %q, want %q (%v)", got, want, err)
			}
		})
	}
}

func TestEndResultMappingExhaustive(t *testing.T) {
	want := map[string]string{
		"USER_REFUSED": ReasonRefused, "USER_REFUSED_CERT_CHOICE": ReasonRefused, "USER_REFUSED_INTERACTION": ReasonRefused,
		"TIMEOUT": ReasonExpired, "WRONG_VC": ReasonWrongCode, "DOCUMENT_UNUSABLE": ReasonAccountUnusable,
		"ACCOUNT_UNUSABLE": ReasonAccountUnusable, "REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP": ReasonUpstreamError,
		"PROTOCOL_FAILURE": ReasonUpstreamError, "EXPECTED_LINKED_SESSION": ReasonUpstreamError, "SERVER_ERROR": ReasonUpstreamError,
		"SOMETHING_NEW": ReasonUnknownEndResult, "ok": ReasonUnknownEndResult,
	}
	for end, reason := range want {
		st, err := ParseStatus([]byte(`{"state":"COMPLETE","result":{"endResult":"` + end + `"}}`))
		if err != nil {
			t.Fatal(err)
		}
		if got := ReasonOf(Outcome(st)); got != reason {
			t.Errorf("%s -> %s, want %s", end, got, reason)
		}
	}
	if Outcome(&Status{State: "COMPLETE", Result: nil}) == nil || Outcome(nil) == nil {
		t.Fatal("nil result must fail")
	}
	for _, body := range []string{``, `{`, `[]`, `{"state":"PAUSED"}`, `{"state":"COMPLETE"}`, `{"state":"COMPLETE","result":{}}`, strings.Repeat(" ", MaxStatusBody+1)} {
		if _, err := ParseStatus([]byte(body)); ReasonOf(err) != ReasonUnknownEndResult {
			t.Errorf("body %.20q: %v", body, err)
		}
	}
	if st, err := ParseStatus([]byte(`{"state":"RUNNING","unknownField":{"deep":1}}`)); err != nil || st.State != "RUNNING" {
		t.Fatal("RUNNING with unknown fields must parse")
	}
}

func TestRevocationUnavailableFailsFlow(t *testing.T) {
	sy := newSynth(t, FlowQR, smartidtest.LeafOptions{})
	sy.c.cfg.Status = statusFn(func(context.Context, *x509.Certificate, *x509.Certificate) error { return errors.New("stale") })
	if _, err := sy.verify(); ReasonOf(err) != ReasonStatusUnavailable {
		t.Fatalf("got %v", err)
	}
}

func FuzzParseStatus(f *testing.F) {
	f.Add([]byte(`{"state":"RUNNING"}`))
	f.Add([]byte(`{"state":"COMPLETE","result":{"endResult":"OK","documentNumber":"PNOEE-40404040009-MOCK-Q"},"signatureProtocol":"ACSP_V2","signature":{"value":"AA==","serverRandom":"AAAAAAAAAAAAAAAAAAAAAAAA","userChallenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","flowType":"QR","signatureAlgorithm":"rsassa-pss","signatureAlgorithmParameters":{"hashAlgorithm":"SHA-512","saltLength":64}},"cert":{"value":"AA==","certificateLevel":"QUALIFIED"},"interactionTypeUsed":"displayTextAndPIN"}`))
	sy := newSynth(&testing.T{}, FlowQR, smartidtest.LeafOptions{})
	good, _ := json.Marshal(sy.st)
	f.Add(good)
	f.Fuzz(func(t *testing.T, b []byte) {
		st, err := ParseStatus(b)
		if err != nil {
			return
		}
		if st.State == "COMPLETE" {
			_ = Outcome(st)
			// A fuzzed body must never verify against a fresh session: the
			// challenge is unpredictable to the fuzzer.
			s2 := newSynth(t, FlowQR, smartidtest.LeafOptions{})
			if id, err := s2.c.Verify(s2.s, st, nil); err == nil || id != nil {
				t.Fatalf("fuzzed status verified")
			}
		}
	})
}
