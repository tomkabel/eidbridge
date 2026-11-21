// Package walletsim is a simulated EUDI Wallet and PID provider for tests,
// the bridge's mock mode and the conformance harness (Story 6.2). It issues
// SD-JWT VC PIDs from a generated PKI and builds presentations, valid or
// deliberately malformed. Identities are synthetic test data.
package walletsim

import (
	"bytes"
	"compress/zlib"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var b64 = base64.RawURLEncoding

// PID is the synthetic person the wallet holds.
var PID = map[string]any{"given_name": "MARI", "family_name": "TEST", "birthdate": "1990-05-17",
	"personal_administrative_number": "49005170005", "issuing_country": "EE", "nationalities": []any{"EE"}}

// Provider is a PID provider: root, issuing CA and a status list.
type Provider struct {
	Root, Inter, Signer *x509.Certificate
	rootKey, interKey   *ecdsa.PrivateKey
	signerKey           *ecdsa.PrivateKey
	// StatusURI is placed in issued credentials when set.
	StatusURI string
	// StatusBits is the status list entry width (1, 2, 4 or 8); 0 means 2.
	StatusBits int

	mu     sync.Mutex
	status map[int]byte
	next   int
}

func newKey() *ecdsa.PrivateKey { k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader); return k }

// NewProvider generates the provider PKI.
func NewProvider(name string) *Provider {
	p := &Provider{rootKey: newKey(), interKey: newKey(), signerKey: newKey(), status: map[int]byte{}}
	now := time.Now()
	mk := func(t *x509.Certificate, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
		d, err := x509.CreateCertificate(rand.Reader, t, parent, pub, signer)
		if err != nil {
			panic(err)
		}
		c, _ := x509.ParseCertificate(d)
		return c
	}
	rt := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name + " TEST PID ROOT"}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(10 * 365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	p.Root = mk(rt, rt, &p.rootKey.PublicKey, p.rootKey)
	it := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name + " TEST PID CA"}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(5 * 365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign}
	p.Inter = mk(it, p.Root, &p.interKey.PublicKey, p.rootKey)
	st := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: name + " TEST PID PROVIDER"}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(2 * 365 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true}
	p.Signer = mk(st, p.Inter, &p.signerKey.PublicKey, p.interKey)
	return p
}

// Wallet holds one credential and its holder key.
type Wallet struct {
	Provider  *Provider
	HolderKey *ecdsa.PrivateKey
	Issuer    string
	// Credential parts: issuer JWT and disclosures by claim name.
	IssuerJWT   string
	Disclosures map[string]string
	StatusIdx   int
}

// IssueOptions varies the issued credential.
type IssueOptions struct {
	VCT       string // default urn:eudi:pid:1
	Expired   bool
	NoExp     bool
	Typ       string // header typ, default dc+sd-jwt
	NoCnf     bool
	SignWith  *ecdsa.PrivateKey // sign with another key (untrusted)
	X5C       []*x509.Certificate
	Claims    map[string]any // default PID
	SDAlg     string         // default sha-256
	AlwaysVis []string       // claims issued in clear (not selectively disclosable)
	// AlsoSD also issues each AlwaysVis claim as a disclosure (a credential
	// that would let a disclosure overwrite a clear claim).
	AlsoSD bool
}

func enc(v any) string { b, _ := json.Marshal(v); return b64.EncodeToString(b) }

func sign(k *ecdsa.PrivateKey, h map[string]any, claims any) string {
	in := enc(h) + "." + enc(claims)
	d := sha256.Sum256([]byte(in))
	r, s, _ := ecdsa.Sign(rand.Reader, k, d[:])
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return in + "." + b64.EncodeToString(sig)
}

// Issue creates a wallet holding a new PID credential.
func (p *Provider) Issue(o IssueOptions) *Wallet {
	w := &Wallet{Provider: p, HolderKey: newKey(), Issuer: "https://pid.example.test", Disclosures: map[string]string{}}
	if o.VCT == "" {
		o.VCT = "urn:eudi:pid:1"
	}
	if o.Typ == "" {
		o.Typ = "dc+sd-jwt"
	}
	if o.Claims == nil {
		o.Claims = PID
	}
	if o.SDAlg == "" {
		o.SDAlg = "sha-256"
	}
	now := time.Now()
	c := map[string]any{"iss": w.Issuer, "vct": o.VCT, "iat": now.Add(-time.Minute).Unix(), "_sd_alg": o.SDAlg}
	if !o.NoExp {
		c["exp"] = now.Add(365 * 24 * time.Hour).Unix()
	}
	if o.Expired {
		c["exp"] = now.Add(-time.Hour).Unix()
	}
	if !o.NoCnf {
		pub := w.HolderKey.PublicKey
		n := 32
		x, y := make([]byte, n), make([]byte, n)
		pub.X.FillBytes(x)
		pub.Y.FillBytes(y)
		c["cnf"] = map[string]any{"jwk": map[string]string{"kty": "EC", "crv": "P-256", "x": b64.EncodeToString(x), "y": b64.EncodeToString(y)}}
	}
	if p.StatusURI != "" {
		p.mu.Lock()
		w.StatusIdx = p.next
		p.next++
		p.mu.Unlock()
		c["status"] = map[string]any{"status_list": map[string]any{"idx": w.StatusIdx, "uri": p.StatusURI}}
	}
	var sd []string
	for k, v := range o.Claims {
		if contains(o.AlwaysVis, k) {
			c[k] = v
			if !o.AlsoSD {
				continue
			}
		}
		d := enc([]any{random16(), k, v})
		w.Disclosures[k] = d
		sum := sha256.Sum256([]byte(d))
		sd = append(sd, b64.EncodeToString(sum[:]))
	}
	sd = append(sd, b64.EncodeToString(sha256.New().Sum([]byte("decoy"))[:32])) // decoy digest
	c["_sd"] = sd
	key := p.signerKey
	if o.SignWith != nil {
		key = o.SignWith
	}
	x5c := o.X5C
	if x5c == nil {
		x5c = []*x509.Certificate{p.Signer, p.Inter}
	}
	var chain []string
	for _, cert := range x5c {
		chain = append(chain, base64.StdEncoding.EncodeToString(cert.Raw))
	}
	w.IssuerJWT = sign(key, map[string]any{"alg": "ES256", "typ": o.Typ, "x5c": chain}, c)
	return w
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func random16() string {
	b := make([]byte, 16)
	rand.Read(b)
	return b64.EncodeToString(b)
}

// PresentOptions varies a presentation for negative tests.
type PresentOptions struct {
	Disclose      []string // default: every claim
	Nonce, Aud    string   // from the request unless overridden
	IAT           time.Time
	NoKB          bool
	KBTyp         string            // default kb+jwt
	KBKey         *ecdsa.PrivateKey // sign the KB-JWT with another key
	BadSDHash     bool
	ExtraDisclose string // append a disclosure the credential does not reference
	DupDisclosure bool
	TamperIssuer  bool // flip a payload byte of the issuer JWT
}

// Present builds an SD-JWT+KB presentation.
func (w *Wallet) Present(nonce, aud string, o PresentOptions) string {
	if o.Nonce == "" {
		o.Nonce = nonce
	}
	if o.Aud == "" {
		o.Aud = aud
	}
	if o.IAT.IsZero() {
		o.IAT = time.Now()
	}
	issuer := w.IssuerJWT
	if o.TamperIssuer {
		parts := strings.Split(issuer, ".")
		pl, _ := b64.DecodeString(parts[1])
		pl = bytes.Replace(pl, []byte(`"vct"`), []byte(`"vcT"`), 1)
		pl = bytes.Replace(pl, []byte(`"vcT"`), []byte(`"vct"`), 1)
		pl = append(pl[:len(pl)-1], []byte(`,"x":1}`)...)
		parts[1] = b64.EncodeToString(pl)
		issuer = strings.Join(parts, ".")
	}
	sdp := issuer + "~"
	names := o.Disclose
	if names == nil {
		for k := range w.Disclosures {
			names = append(names, k)
		}
	}
	for _, n := range names {
		if d, ok := w.Disclosures[n]; ok {
			sdp += d + "~"
			if o.DupDisclosure {
				sdp += d + "~"
				o.DupDisclosure = false
			}
		}
	}
	if o.ExtraDisclose != "" {
		sdp += enc([]any{random16(), o.ExtraDisclose, "injected"}) + "~"
	}
	if o.NoKB {
		return sdp
	}
	sum := sha256.Sum256([]byte(sdp))
	sh := b64.EncodeToString(sum[:])
	if o.BadSDHash {
		sh = b64.EncodeToString(make([]byte, 32))
	}
	typ := o.KBTyp
	if typ == "" {
		typ = "kb+jwt"
	}
	key := w.HolderKey
	if o.KBKey != nil {
		key = o.KBKey
	}
	return sdp + sign(key, map[string]any{"alg": "ES256", "typ": typ}, map[string]any{"nonce": o.Nonce, "aud": o.Aud, "iat": o.IAT.Unix(), "sd_hash": sh})
}

// Request is the parsed part of a request object the wallet uses.
type Request struct {
	ClientID, ResponseURI, Nonce, State, ResponseMode string
	Claims                                            []string
}

// FetchRequest resolves an openid4vp:// link: fetches the request object
// (signature checked against the x5c leaf only; wallets would also check
// trust) and checks the x509_hash client identifier.
func FetchRequest(hc *http.Client, link string) (*Request, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Get(u.Query().Get("request_uri"))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/oauth-authz-req+jwt" {
		return nil, errors.New("request object not served as application/oauth-authz-req+jwt")
	}
	return ParseRequest(link, buf.String())
}

// ParseRequest checks a request object JWS for an openid4vp:// link.
func ParseRequest(link, jws string) (*Request, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimSpace(jws), ".")
	if len(parts) != 3 {
		return nil, errors.New("request object is not a JWS")
	}
	var h struct {
		Typ string   `json:"typ"`
		X5C []string `json:"x5c"`
	}
	hb, _ := b64.DecodeString(parts[0])
	json.Unmarshal(hb, &h)
	if h.Typ != "oauth-authz-req+jwt" || len(h.X5C) == 0 {
		return nil, errors.New("request object header")
	}
	der, _ := base64.StdEncoding.DecodeString(h.X5C[0])
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	d := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	sig, _ := b64.DecodeString(parts[2])
	if len(sig) != 64 || !ecdsa.Verify(leaf.PublicKey.(*ecdsa.PublicKey), d[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return nil, errors.New("request object signature")
	}
	pb, _ := b64.DecodeString(parts[1])
	var ro struct {
		ClientID     string `json:"client_id"`
		ResponseURI  string `json:"response_uri"`
		ResponseMode string `json:"response_mode"`
		Nonce        string `json:"nonce"`
		State        string `json:"state"`
		DCQL         struct {
			Credentials []struct {
				Claims []struct {
					Path []string `json:"path"`
				} `json:"claims"`
			} `json:"credentials"`
		} `json:"dcql_query"`
	}
	if json.Unmarshal(pb, &ro) != nil {
		return nil, errors.New("request object payload")
	}
	hash := sha256.Sum256(leaf.Raw)
	if ro.ClientID != "x509_hash:"+b64.EncodeToString(hash[:]) || u.Query().Get("client_id") != ro.ClientID {
		return nil, errors.New("client_id does not match the x5c leaf")
	}
	r := &Request{ClientID: ro.ClientID, ResponseURI: ro.ResponseURI, Nonce: ro.Nonce, State: ro.State, ResponseMode: ro.ResponseMode}
	for _, c := range ro.DCQL.Credentials {
		for _, cl := range c.Claims {
			r.Claims = append(r.Claims, strings.Join(cl.Path, "."))
		}
	}
	return r, nil
}

// Respond posts a direct_post response with the given vp_token JSON value.
func Respond(hc *http.Client, r *Request, vpToken string, extra url.Values) (*http.Response, error) {
	f := url.Values{"vp_token": {vpToken}, "state": {r.State}}
	for k, v := range extra {
		f[k] = v
	}
	return hc.PostForm(r.ResponseURI, f)
}

// VPToken wraps one presentation as the DCQL vp_token object.
func VPToken(presentation string) string {
	b, _ := json.Marshal(map[string][]string{"pid": {presentation}})
	return string(b)
}

// SetStatus sets a status list entry (0 valid, 1 revoked, 2 suspended).
func (p *Provider) SetStatus(idx int, v byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.status[idx] = v
}

// StatusHandler serves the 1-bit... 8-bit status list token (bits=2).
func (p *Provider) StatusHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		bits := p.StatusBits
		if bits == 0 {
			bits = 2
		}
		n := p.next + 8
		raw := make([]byte, (n*bits+7)/8)
		for i, v := range p.status {
			raw[i*bits/8] |= (v & byte(1<<bits-1)) << (uint(i*bits) % 8)
		}
		p.mu.Unlock()
		var zb bytes.Buffer
		zw := zlib.NewWriter(&zb)
		zw.Write(raw)
		zw.Close()
		now := time.Now()
		tok := sign(p.signerKey, map[string]any{"alg": "ES256", "typ": "statuslist+jwt",
			"x5c": []string{base64.StdEncoding.EncodeToString(p.Signer.Raw), base64.StdEncoding.EncodeToString(p.Inter.Raw)}},
			map[string]any{"sub": p.StatusURI, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
				"status_list": map[string]any{"bits": bits, "lst": b64.EncodeToString(zb.Bytes())}})
		w.Header().Set("Content-Type", "application/statuslist+jwt")
		w.Write([]byte(tok))
	})
}

// SignerCertWithKeyUsage issues another certificate for the provider
// signing key with the given key usage (negative tests).
func (p *Provider) SignerCertWithKeyUsage(ku x509.KeyUsage) *x509.Certificate {
	now := time.Now()
	t := &x509.Certificate{SerialNumber: big.NewInt(4), Subject: pkix.Name{CommonName: "TEST PID PROVIDER KU"}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(24 * time.Hour), KeyUsage: ku, BasicConstraintsValid: true}
	d, err := x509.CreateCertificate(rand.Reader, t, p.Inter, &p.signerKey.PublicKey, p.interKey)
	if err != nil {
		panic(err)
	}
	c, _ := x509.ParseCertificate(d)
	return c
}

// SignerKey exposes the provider signing key for negative tests that need
// a correctly signed but otherwise wrong credential.
func (p *Provider) SignerKey() *ecdsa.PrivateKey { return p.signerKey }
