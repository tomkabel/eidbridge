package eudi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
	"github.com/tomkabel/eidbridge/internal/smartid"
)

// Verifier checks SD-JWT VC presentations.
type Verifier struct {
	// Trust holds the PID provider (issuer) CA certificates; the issuer JWT
	// x5c chain must end in one of them.
	Trust *smartid.TrustStore
	// VCTs lists the accepted credential types, e.g. urn:eudi:pid:1.
	VCTs []string
	// Status checks Token Status List references; nil means a credential
	// with a status reference fails closed.
	Status *StatusChecker
	// RequireStatus refuses credentials without a status reference.
	RequireStatus bool
	Skew          time.Duration // allowed clock skew, default 60 s
	KBMaxAge      time.Duration // key-binding JWT iat window, default 5 min
	Now           func() time.Time
}

// Presentation is what the verifier learned from one valid presentation:
// only disclosed claims, plus the issuer.
type Presentation struct {
	Issuer string
	VCT    string
	Claims map[string]any
}

func vfail(format string, a ...any) error {
	return &authn.Error{Reason: authn.ReasonVerificationFailed, Detail: fmt.Sprintf(format, a...)}
}

// MaxPresentation bounds an SD-JWT presentation.
const MaxPresentation = 128 << 10

// Verify checks one SD-JWT+KB presentation for the given request nonce and
// client identifier. Steps, failing closed:
//
//  1. structure: issuer JWT ~ disclosures ~ key-binding JWT (KB required)
//  2. issuer JWT: allowed ES algorithm, typ dc+sd-jwt, x5c chain to a
//     configured PID provider CA, signature by the x5c leaf
//  3. issuer claims: vct accepted, iat/nbf/exp within skew, _sd_alg sha-256,
//     cnf.jwk holder key present
//  4. disclosures: well-formed, each digest referenced exactly once, no
//     reserved or duplicate claim names; undisclosed digests stay hidden
//  5. key binding: typ kb+jwt, signed by cnf.jwk, nonce and aud equal the
//     request, iat within the window, sd_hash over the presented SD-JWT
//  6. status: Token Status List entry VALID (unknown fails closed)
func (v *Verifier) Verify(ctx context.Context, presentation, nonce, clientID string) (*Presentation, error) {
	if len(presentation) == 0 || len(presentation) > MaxPresentation {
		return nil, vfail("presentation empty or too large")
	}
	// 1
	parts := strings.Split(presentation, "~")
	if len(parts) < 2 {
		return nil, vfail("not an SD-JWT")
	}
	kb := parts[len(parts)-1]
	if kb == "" {
		return nil, vfail("key-binding JWT missing")
	}
	issuerJWT, disclosures := parts[0], parts[1:len(parts)-1]
	sdPart := presentation[:len(presentation)-len(kb)] // issuer~d1~...~dn~
	now := v.Now()
	skew := v.Skew
	if skew == 0 {
		skew = 60 * time.Second
	}
	// 2
	h, payload, in, sig, err := parseJWS(issuerJWT)
	if err != nil {
		return nil, vfail("issuer JWT: %v", err)
	}
	if h.Typ != "dc+sd-jwt" && h.Typ != "vc+sd-jwt" {
		return nil, vfail("issuer JWT typ is not dc+sd-jwt")
	}
	chain, err := x5cChain(h.X5C)
	if err != nil {
		return nil, vfail("issuer JWT: %v", err)
	}
	inter := v.Trust.Intermediates.Clone()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{Roots: v.Trust.Roots, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, vfail("issuer certificate does not chain to a configured PID provider CA")
	}
	if chain[0].KeyUsage != 0 && chain[0].KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, vfail("issuer certificate is not for signatures")
	}
	if err := verifyES(h.Alg, chain[0].PublicKey, in, sig); err != nil {
		return nil, vfail("issuer JWT: %v", err)
	}
	// 3
	var c map[string]any
	dec := json.NewDecoder(strings.NewReader(string(payload)))
	dec.UseNumber()
	if dec.Decode(&c) != nil {
		return nil, vfail("issuer JWT payload is not a JSON object")
	}
	vct, _ := c["vct"].(string)
	if !contains(v.VCTs, vct) {
		return nil, vfail("credential type not accepted")
	}
	iss, _ := c["iss"].(string)
	if iss == "" {
		return nil, vfail("issuer JWT has no iss")
	}
	if err := timeClaims(c, now, skew, true); err != nil {
		return nil, err
	}
	if alg, ok := c["_sd_alg"]; ok && alg != "sha-256" {
		return nil, vfail("_sd_alg is not sha-256")
	}
	cnf, _ := c["cnf"].(map[string]any)
	jwkRaw, _ := json.Marshal(cnf["jwk"])
	holder, err := ecJWK(jwkRaw)
	if cnf == nil || err != nil {
		return nil, vfail("cnf.jwk holder key missing or invalid")
	}
	// 4
	byDigest := map[string]disclosure{}
	for _, d := range disclosures {
		if d == "" {
			return nil, vfail("empty disclosure")
		}
		ds, err := parseDisclosure(d)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256([]byte(d))
		dg := b64.EncodeToString(sum[:])
		if _, dup := byDigest[dg]; dup {
			return nil, vfail("disclosure repeated")
		}
		byDigest[dg] = ds
	}
	used := map[string]bool{}
	claims, err := resolve(c, byDigest, used, 0)
	if err != nil {
		return nil, err
	}
	if len(used) != len(byDigest) {
		return nil, vfail("disclosure not referenced by the credential")
	}
	// 5
	kh, kp, kin, ksig, err := parseJWS(kb)
	if err != nil {
		return nil, vfail("key-binding JWT: %v", err)
	}
	if kh.Typ != "kb+jwt" {
		return nil, vfail("key-binding JWT typ is not kb+jwt")
	}
	if err := verifyES(kh.Alg, holder, kin, ksig); err != nil {
		return nil, vfail("key-binding JWT: %v", err)
	}
	var k map[string]any
	kd := json.NewDecoder(strings.NewReader(string(kp)))
	kd.UseNumber()
	if kd.Decode(&k) != nil {
		return nil, vfail("key-binding JWT payload is not a JSON object")
	}
	if n, _ := k["nonce"].(string); subtle.ConstantTimeCompare([]byte(n), []byte(nonce)) != 1 || nonce == "" {
		return nil, vfail("key-binding nonce does not match the request")
	}
	if a, _ := k["aud"].(string); a != clientID {
		return nil, vfail("key-binding aud is not this verifier")
	}
	iat, ok := num(k["iat"])
	maxAge := v.KBMaxAge
	if maxAge == 0 {
		maxAge = 5 * time.Minute
	}
	if !ok || time.Unix(iat, 0).After(now.Add(skew)) || time.Unix(iat, 0).Before(now.Add(-maxAge)) {
		return nil, vfail("key-binding iat outside the window")
	}
	sum := sha256.Sum256([]byte(sdPart))
	if sh, _ := k["sd_hash"].(string); subtle.ConstantTimeCompare([]byte(sh), []byte(b64.EncodeToString(sum[:]))) != 1 {
		return nil, vfail("key-binding sd_hash does not match the presentation")
	}
	// 6
	if st, ok := c["status"]; ok {
		if v.Status == nil {
			return nil, &authn.Error{Reason: authn.ReasonStatusUnavailable, Detail: "credential has a status reference but no checker is configured"}
		}
		if err := v.Status.Check(ctx, st, v.Trust, now); err != nil {
			return nil, err
		}
	} else if v.RequireStatus {
		return nil, vfail("credential has no status reference")
	}
	delete(claims, "cnf")
	delete(claims, "status")
	return &Presentation{Issuer: iss, VCT: vct, Claims: claims}, nil
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func num(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	return i, err == nil
}

// timeClaims checks iat, nbf and exp. exp is required for credentials.
func timeClaims(c map[string]any, now time.Time, skew time.Duration, needExp bool) error {
	if v, ok := c["nbf"]; ok {
		n, ok := num(v)
		if !ok || time.Unix(n, 0).After(now.Add(skew)) {
			return vfail("credential not yet valid")
		}
	}
	if v, ok := c["iat"]; ok {
		n, ok := num(v)
		if !ok || time.Unix(n, 0).After(now.Add(skew)) {
			return vfail("credential issued in the future")
		}
	}
	v, ok := c["exp"]
	if !ok {
		if needExp {
			return vfail("credential has no exp")
		}
		return nil
	}
	n, ok := num(v)
	if !ok || !now.Add(-skew).Before(time.Unix(n, 0)) {
		return vfail("credential expired")
	}
	return nil
}

type disclosure struct {
	name  string // empty for array elements
	value any
}

var reserved = map[string]bool{"_sd": true, "...": true, "_sd_alg": true}

func parseDisclosure(s string) (disclosure, error) {
	raw, err := b64.DecodeString(s)
	if err != nil {
		return disclosure{}, vfail("disclosure is not base64url")
	}
	var arr []any
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.UseNumber()
	if d.Decode(&arr) != nil {
		return disclosure{}, vfail("disclosure is not a JSON array")
	}
	switch len(arr) {
	case 3:
		name, ok := arr[1].(string)
		if _, salt := arr[0].(string); !salt || !ok || reserved[name] {
			return disclosure{}, vfail("malformed object disclosure")
		}
		return disclosure{name: name, value: arr[2]}, nil
	case 2:
		if _, salt := arr[0].(string); !salt {
			return disclosure{}, vfail("malformed array disclosure")
		}
		return disclosure{value: arr[1]}, nil
	}
	return disclosure{}, vfail("disclosure has the wrong length")
}

// resolve replaces _sd digests and {"...": digest} array entries with the
// disclosed values (RFC 9901 §7.1), recursively, and removes SD metadata.
func resolve(obj map[string]any, byDigest map[string]disclosure, used map[string]bool, depth int) (map[string]any, error) {
	if depth > 8 {
		return nil, vfail("credential nested too deeply")
	}
	out := map[string]any{}
	for k, val := range obj {
		if k == "_sd" || k == "_sd_alg" {
			continue
		}
		r, err := resolveValue(val, byDigest, used, depth)
		if err != nil {
			return nil, err
		}
		out[k] = r
	}
	if sd, ok := obj["_sd"]; ok {
		list, ok := sd.([]any)
		if !ok {
			return nil, vfail("_sd is not an array")
		}
		for _, x := range list {
			dg, ok := x.(string)
			if !ok {
				return nil, vfail("_sd entry is not a string")
			}
			ds, found := byDigest[dg]
			if !found {
				continue // not disclosed
			}
			if used[dg] {
				return nil, vfail("digest referenced twice")
			}
			used[dg] = true
			if ds.name == "" {
				return nil, vfail("array disclosure used as object property")
			}
			if _, exists := out[ds.name]; exists {
				return nil, vfail("disclosed claim name already present")
			}
			r, err := resolveValue(ds.value, byDigest, used, depth+1)
			if err != nil {
				return nil, err
			}
			out[ds.name] = r
		}
	}
	return out, nil
}

func resolveValue(val any, byDigest map[string]disclosure, used map[string]bool, depth int) (any, error) {
	switch t := val.(type) {
	case map[string]any:
		return resolve(t, byDigest, used, depth+1)
	case []any:
		var out []any
		for _, e := range t {
			if m, ok := e.(map[string]any); ok && len(m) == 1 {
				if dg, ok := m["..."].(string); ok {
					ds, found := byDigest[dg]
					if !found {
						continue
					}
					if used[dg] {
						return nil, vfail("digest referenced twice")
					}
					used[dg] = true
					if ds.name != "" {
						return nil, vfail("object disclosure used as array element")
					}
					r, err := resolveValue(ds.value, byDigest, used, depth+1)
					if err != nil {
						return nil, err
					}
					out = append(out, r)
					continue
				}
			}
			r, err := resolveValue(e, byDigest, used, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, r)
		}
		return out, nil
	}
	return val, nil
}
