package oidc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

// Access token layout (ADR-008): format byte | key version (2 bytes) |
// 12-byte nonce | AES-256-GCM ciphertext and tag. Associated data binds the
// label "eidbridge-at-v1", the format and the key version. K_at lives only in
// process memory, so a restart invalidates every outstanding token.
const (
	atFormat = 1
	atLabel  = "eidbridge-at-v1"
)

type sealedPayload struct {
	ClientID string            `json:"cid"`
	Family   string            `json:"fam"`
	Epoch    string            `json:"ep"`
	Deadline int64             `json:"dl"` // process-monotonic acceptance deadline, ns
	IAT      int64             `json:"iat"`
	EXP      int64             `json:"exp"`
	Claims   map[string]any    `json:"c"`
	Scope    []string          `json:"s,omitempty"`
	Extra    map[string]string `json:"x,omitempty"`
}

// Sealer seals and opens access tokens.
type Sealer struct {
	mu      sync.RWMutex
	epoch   string
	current uint16
	keys    map[uint16]cipher.AEAD
}

// NewSealer creates a fresh in-memory key and process epoch.
func NewSealer() (*Sealer, error) {
	s := &Sealer{keys: map[uint16]cipher.AEAD{}}
	e := make([]byte, 16)
	if _, err := rand.Read(e); err != nil {
		return nil, err
	}
	s.epoch = base64.RawURLEncoding.EncodeToString(e)
	return s, s.Rotate()
}

// Rotate adds a new sealing key version and makes it current. Older
// versions are dropped (emergency revocation rotates K_at).
func (s *Sealer) Rotate() error {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return err
	}
	blk, _ := aes.NewCipher(k)
	g, _ := cipher.NewGCM(blk)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.current++
	s.keys = map[uint16]cipher.AEAD{s.current: g}
	return nil
}

// Epoch returns the process epoch.
func (s *Sealer) Epoch() string { return s.epoch }

func ad(version uint16) []byte {
	b := []byte(atLabel)
	b = append(b, atFormat, byte(version>>8), byte(version))
	return b
}

func (s *Sealer) seal(p sealedPayload) (string, error) {
	s.mu.RLock()
	v, g := s.current, s.keys[s.current]
	s.mu.RUnlock()
	p.Epoch = s.epoch
	pt, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := []byte{atFormat, byte(v >> 8), byte(v)}
	out = append(out, nonce...)
	out = g.Seal(out, nonce, pt, ad(v))
	return base64.RawURLEncoding.EncodeToString(out), nil
}

var errToken = errors.New("invalid token")

func (s *Sealer) open(tok string) (sealedPayload, error) {
	var p sealedPayload
	if len(tok) > 8192 {
		return p, errToken
	}
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil || len(raw) < 3+12+16 || raw[0] != atFormat {
		return p, errToken
	}
	v := binary.BigEndian.Uint16(raw[1:3])
	s.mu.RLock()
	g := s.keys[v]
	s.mu.RUnlock()
	if g == nil {
		return p, errToken
	}
	pt, err := g.Open(nil, raw[3:15], raw[15:], ad(v))
	if err != nil {
		return p, errToken
	}
	if err := json.Unmarshal(pt, &p); err != nil || p.Epoch != s.epoch {
		return p, errToken
	}
	return p, nil
}

// checkLifetime applies the ADR-008 userinfo rules except the family check.
func checkLifetime(p sealedPayload, maxLife time.Duration, wallNow time.Time, mono time.Duration) error {
	life := p.EXP - p.IAT
	if life <= 0 || time.Duration(life)*time.Second > maxLife {
		return errToken
	}
	if wallNow.Unix() >= p.EXP || int64(mono) >= p.Deadline {
		return errToken
	}
	return nil
}
