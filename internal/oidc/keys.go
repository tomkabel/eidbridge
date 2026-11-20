package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tomkabel/eidbridge/internal/jose"
)

// KeyEntry is one manifest row. Retired keys stay in JWKS until NotAfter and
// survive restarts because the manifest persists (ADR-007).
type KeyEntry struct {
	KID      string    `json:"kid"`
	Alg      string    `json:"alg"`
	File     string    `json:"file"`
	Status   string    `json:"status"` // active or retired
	NotAfter time.Time `json:"not_after,omitempty"`
}

// KeySet holds the signing keys. It is operator state, not user data.
type KeySet struct {
	mu      sync.RWMutex
	dir     string
	demo    bool
	entries []KeyEntry
	keys    map[string]*jose.Key
	now     func() time.Time
}

const manifestName = "keys.json"

// FixtureFingerprints are SPKI SHA-256 fingerprints (hex) of keys committed
// to this repository for tests. Production refuses them.
var FixtureFingerprints = map[string]bool{}

// SPKIFingerprint returns the hex SHA-256 of a public key's SPKI.
func SPKIFingerprint(pub crypto.PublicKey) string {
	der, _ := x509.MarshalPKIXPublicKey(pub)
	s := sha256.Sum256(der)
	return hex.EncodeToString(s[:])
}

// LoadKeys reads dir/keys.json. In demo mode, a missing manifest creates a
// fresh demo RS256 key (kid "demo-" + thumbprint). Production never
// generates keys and refuses demo-labelled, fixture or deny-listed keys.
func LoadKeys(dir string, demo bool, denyFingerprints []string, now func() time.Time) (*KeySet, error) {
	if now == nil {
		now = time.Now
	}
	deny := map[string]bool{}
	for _, f := range denyFingerprints {
		f = strings.ToLower(strings.TrimSpace(f))
		if len(f) != 64 {
			return nil, fmt.Errorf("oidc: malformed demo-key fingerprint %q in deny-list", f)
		}
		if _, err := hex.DecodeString(f); err != nil {
			return nil, fmt.Errorf("oidc: malformed demo-key fingerprint %q in deny-list", f)
		}
		deny[f] = true
	}
	ks := &KeySet{dir: dir, demo: demo, keys: map[string]*jose.Key{}, now: now}
	b, err := os.ReadFile(filepath.Join(dir, manifestName))
	if errors.Is(err, os.ErrNotExist) {
		if !demo {
			return nil, errors.New("oidc: production requires an operator-supplied signing key (keys.json missing)")
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		if _, err := ks.add(jose.RS256); err != nil {
			return nil, err
		}
		return ks, ks.save()
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &ks.entries); err != nil {
		return nil, fmt.Errorf("oidc: keys.json: %w", err)
	}
	active := map[string]int{}
	var kept []KeyEntry
	for _, e := range ks.entries {
		if e.Status == "retired" && !e.NotAfter.IsZero() && now().After(e.NotAfter) {
			continue // past retention
		}
		k, err := loadKeyFile(filepath.Join(dir, e.File), e.Alg)
		if err != nil {
			return nil, fmt.Errorf("oidc: key %s: %w", e.KID, err)
		}
		tp, _ := jose.Thumbprint(k.Public())
		want := tp
		if demo {
			want = "demo-" + tp
		}
		if e.KID != want {
			return nil, fmt.Errorf("oidc: key %s: kid must be %q in this mode", e.KID, want)
		}
		fp := SPKIFingerprint(k.Public())
		if !demo && (strings.HasPrefix(e.KID, "demo-") || FixtureFingerprints[fp] || deny[fp]) {
			return nil, fmt.Errorf("oidc: production refuses demo, fixture or deny-listed key %s", e.KID)
		}
		k.KID = e.KID
		ks.keys[e.KID] = k
		if e.Status == "active" {
			active[e.Alg]++
		} else if e.Status != "retired" {
			return nil, fmt.Errorf("oidc: key %s: unknown status %q", e.KID, e.Status)
		}
		kept = append(kept, e)
	}
	ks.entries = kept
	if active[jose.RS256] != 1 || active[jose.ES256] > 1 {
		return nil, errors.New("oidc: exactly one active RS256 key and at most one active ES256 key are required")
	}
	return ks, nil
}

func loadKeyFile(path, alg string) (*jose.Key, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("key file %s must have mode 0600", filepath.Base(path))
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("key file is not PEM")
	}
	pk, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	s, ok := pk.(crypto.Signer)
	if !ok {
		return nil, errors.New("unsupported key")
	}
	if err := jose.CheckKey(alg, s.Public()); err != nil {
		return nil, err
	}
	return &jose.Key{Alg: alg, Private: s}, nil
}

func (ks *KeySet) add(alg string) (*jose.Key, error) {
	var s crypto.Signer
	var err error
	switch alg {
	case jose.RS256:
		s, err = rsa.GenerateKey(rand.Reader, demoRSABits)
	case jose.ES256:
		s, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		return nil, errors.New("oidc: unsupported algorithm")
	}
	if err != nil {
		return nil, err
	}
	tp, _ := jose.Thumbprint(s.Public())
	kid := tp
	if ks.demo {
		kid = "demo-" + tp
	}
	der, _ := x509.MarshalPKCS8PrivateKey(s)
	file := kid + ".pem"
	if err := os.WriteFile(filepath.Join(ks.dir, file), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	k := &jose.Key{KID: kid, Alg: alg, Private: s}
	ks.keys[kid] = k
	ks.entries = append(ks.entries, KeyEntry{KID: kid, Alg: alg, File: file, Status: "active"})
	return k, nil
}

func (ks *KeySet) save() error {
	b, _ := json.MarshalIndent(ks.entries, "", "  ")
	tmp := filepath.Join(ks.dir, manifestName+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(ks.dir, manifestName))
}

// Rotate performs a planned rotation: a new active key for alg; the old one
// is retired and stays in JWKS until retain from now (longest token expiry
// plus clock skew).
func (ks *KeySet) Rotate(alg string, retain time.Duration) (string, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	for i := range ks.entries {
		if ks.entries[i].Alg == alg && ks.entries[i].Status == "active" {
			ks.entries[i].Status = "retired"
			ks.entries[i].NotAfter = ks.now().Add(retain).UTC()
		}
	}
	k, err := ks.add(alg)
	if err != nil {
		return "", err
	}
	return k.KID, ks.save()
}

// Revoke is the emergency procedure: activate a replacement if kid was
// active, then drop kid from JWKS immediately and delete its file.
func (ks *KeySet) Revoke(kid string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	idx := -1
	for i, e := range ks.entries {
		if e.KID == kid {
			idx = i
		}
	}
	if idx < 0 {
		return errors.New("oidc: unknown kid")
	}
	e := ks.entries[idx]
	if e.Status == "active" {
		if _, err := ks.add(e.Alg); err != nil {
			return err
		}
	}
	ks.entries = append(ks.entries[:idx], ks.entries[idx+1:]...)
	delete(ks.keys, kid)
	os.Remove(filepath.Join(ks.dir, e.File))
	return ks.save()
}

// Active returns the active key for alg.
func (ks *KeySet) Active(alg string) (*jose.Key, bool) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	for _, e := range ks.entries {
		if e.Alg == alg && e.Status == "active" {
			return ks.keys[e.KID], true
		}
	}
	return nil, false
}

// JWKS returns the published key set: active keys plus retired keys still
// inside their retention.
func (ks *KeySet) JWKS() []jose.JWK {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	var out []jose.JWK
	now := ks.now()
	for _, e := range ks.entries {
		if e.Status == "retired" && !e.NotAfter.IsZero() && now.After(e.NotAfter) {
			continue
		}
		j, err := jose.PublicJWK(ks.keys[e.KID].Public(), e.KID, e.Alg)
		if err == nil {
			out = append(out, j)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].KID < out[j].KID })
	return out
}

// PublicKeys returns verification keys for (alg, kid) from the JWKS view.
func (ks *KeySet) PublicKeys(alg, kid string) []crypto.PublicKey {
	var out []crypto.PublicKey
	for _, j := range ks.JWKS() {
		if j.Alg == alg && (kid == "" || j.KID == kid) {
			if k, err := j.Key(); err == nil {
				out = append(out, k)
			}
		}
	}
	return out
}

// Entries returns a copy of the manifest (for `eidbridge keys list`).
func (ks *KeySet) Entries() []KeyEntry {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return append([]KeyEntry(nil), ks.entries...)
}

// EmergencyRevoke runs the emergency procedure (ADR-007): activate a
// replacement signing key, drop the compromised key from JWKS now, rotate the
// access-token sealing key and revoke every token family, so clients must
// re-authenticate.
func EmergencyRevoke(p *Provider, kid string) error {
	if err := p.cfg.Keys.Revoke(kid); err != nil {
		return err
	}
	p.cfg.Codes.RevokeAll()
	return p.sealer.Rotate()
}

// demoRSABits is the size of generated RSA keys (3,072 recommended by
// ADR-007). Tests lower it to keep the suite fast.
var demoRSABits = 3072
