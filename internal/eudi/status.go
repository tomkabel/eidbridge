package eudi

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
	"github.com/tomkabel/eidbridge/internal/smartid"
)

// StatusChecker resolves Token Status List references (draft-ietf-oauth-
// status-list) from allow-listed hosts. Status list tokens must be signed
// by a certificate chaining to the same PID provider trust.
type StatusChecker struct {
	HTTP         *http.Client
	AllowedHosts map[string]bool
	MaxBytes     int64 // default 1 MiB (compressed token and decompressed list)
}

func unavailable(detail string) error {
	return &authn.Error{Reason: authn.ReasonStatusUnavailable, Detail: detail}
}

// Check returns nil only when the referenced entry is VALID (0).
func (s *StatusChecker) Check(ctx context.Context, ref any, trust *smartid.TrustStore, now time.Time) error {
	max := s.MaxBytes
	if max == 0 {
		max = 1 << 20
	}
	var r struct {
		StatusList *struct {
			Idx *int64 `json:"idx"`
			URI string `json:"uri"`
		} `json:"status_list"`
	}
	b, _ := json.Marshal(ref)
	if json.Unmarshal(b, &r) != nil || r.StatusList == nil || r.StatusList.Idx == nil || *r.StatusList.Idx < 0 {
		return vfail("status reference malformed")
	}
	u, err := url.Parse(r.StatusList.URI)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || !s.AllowedHosts[u.Host] {
		return unavailable("status list host not allow-listed")
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	req.Header.Set("Accept", "application/statuslist+jwt")
	hc := s.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return unavailable("status list fetch failed")
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if resp.StatusCode != http.StatusOK || int64(len(body)) > max {
		return unavailable("status list unavailable")
	}
	h, payload, in, sig, err := parseJWS(strings.TrimSpace(string(body)))
	if err != nil || h.Typ != "statuslist+jwt" {
		return unavailable("status list token malformed")
	}
	chain, err := x5cChain(h.X5C)
	if err != nil {
		return unavailable("status list token without x5c")
	}
	inter := trust.Intermediates.Clone()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{Roots: trust.Roots, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return unavailable("status list signer not trusted")
	}
	if verifyES(h.Alg, chain[0].PublicKey, in, sig) != nil {
		return unavailable("status list signature invalid")
	}
	var c map[string]any
	d := json.NewDecoder(bytes.NewReader(payload))
	d.UseNumber()
	if d.Decode(&c) != nil {
		return unavailable("status list payload malformed")
	}
	if sub, _ := c["sub"].(string); sub != r.StatusList.URI {
		return unavailable("status list sub does not match the reference")
	}
	if err := timeClaims(c, now, time.Minute, false); err != nil {
		return unavailable("status list expired or not yet valid")
	}
	sl, _ := c["status_list"].(map[string]any)
	bits, ok := num(sl["bits"])
	lst, _ := sl["lst"].(string)
	if !ok || (bits != 1 && bits != 2 && bits != 4 && bits != 8) || lst == "" {
		return unavailable("status list malformed")
	}
	zb, err := b64.DecodeString(lst)
	if err != nil {
		return unavailable("status list encoding invalid")
	}
	zr, err := zlib.NewReader(bytes.NewReader(zb))
	if err != nil {
		return unavailable("status list compression invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(zr, max+1))
	if err != nil || int64(len(raw)) > max {
		return unavailable("status list too large or corrupt")
	}
	idx := *r.StatusList.Idx
	bit := idx * bits
	if bit/8 >= int64(len(raw)) {
		return unavailable("status index outside the list")
	}
	val := (raw[bit/8] >> (bit % 8)) & byte((1<<bits)-1)
	switch val {
	case 0:
		return nil
	case 1:
		return vfail("credential revoked (status list)")
	case 2:
		return vfail("credential suspended (status list)")
	}
	return vfail("credential status not valid (status list)")
}
