// Package v2test is a synthetic Smart-ID RP API v2 for offline tests and
// the bridge's mock mode, using the v3 fixture PKI. Identities are SK's
// published demo codes.
package v2test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/tomkabel/eidbridge/internal/smartid/smartidtest"
)

// Server answers /authentication/etsi/{id} and /session/{id}.
type Server struct {
	PKI       *smartidtest.PKI
	Scenarios map[string]string // semantics id → endResult (default OK)
	Mutate    func(map[string]any)
	mu        sync.Mutex
	sessions  map[string]*session
	leaves    map[string]*smartidtest.Leaf
}

type session struct {
	hash []byte
	id   string
}

// NewServer returns a server with refusal and timeout identities.
func NewServer() *Server {
	return &Server{PKI: smartidtest.NewPKI("v2"), sessions: map[string]*session{}, leaves: map[string]*smartidtest.Leaf{},
		Scenarios: map[string]string{"PNOEE-30403039917": "USER_REFUSED", "PNOEE-30403039983": "TIMEOUT", "PNOEE-30403039972": "WRONG_VC"}}
}

// Leaf returns (and caches) the certificate for a serial number.
func (s *Server) Leaf(serial string) *smartidtest.Leaf {
	s.mu.Lock()
	defer s.mu.Unlock()
	if l, ok := s.leaves[serial]; ok {
		return l
	}
	l := s.PKI.NewLeaf(smartidtest.LeafOptions{SerialNumber: serial})
	s.leaves[serial] = l
	return l
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	p := r.URL.Path[strings.Index(r.URL.Path+"/v2", "/v2")+3:]
	switch {
	case r.Method == http.MethodPost && strings.HasPrefix(p, "/authentication/etsi/"):
		var req struct {
			Hash, HashType string
		}
		b, _ := io.ReadAll(io.LimitReader(r.Body, 8<<10))
		json.Unmarshal(b, &req)
		h, err := base64.StdEncoding.DecodeString(req.Hash)
		if err != nil || req.HashType != "SHA512" || len(h) != 64 {
			w.WriteHeader(400)
			return
		}
		id := randID()
		s.mu.Lock()
		s.sessions[id] = &session{hash: h, id: strings.TrimPrefix(p, "/authentication/etsi/")}
		s.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]string{"sessionID": id})
	case r.Method == http.MethodGet && strings.HasPrefix(p, "/session/"):
		s.mu.Lock()
		se := s.sessions[strings.TrimPrefix(p, "/session/")]
		s.mu.Unlock()
		if se == nil {
			w.WriteHeader(404)
			return
		}
		end := s.Scenarios[se.id]
		if end == "" {
			end = "OK"
		}
		st := map[string]any{"state": "COMPLETE", "result": map[string]any{"endResult": end}}
		if end == "OK" {
			l := s.Leaf(se.id)
			sig, _ := rsa.SignPKCS1v15(rand.Reader, l.Key.(*rsa.PrivateKey), crypto.SHA512, se.hash)
			st["result"] = map[string]any{"endResult": "OK", "documentNumber": se.id + "-MOCK-Q"}
			st["signature"] = map[string]any{"value": base64.StdEncoding.EncodeToString(sig), "algorithm": "sha512WithRSAEncryption"}
			st["cert"] = map[string]any{"value": base64.StdEncoding.EncodeToString(l.Cert.Raw), "certificateLevel": "QUALIFIED"}
		}
		if s.Mutate != nil {
			s.Mutate(st)
		}
		json.NewEncoder(w).Encode(st)
	default:
		w.WriteHeader(404)
	}
}

func randID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	const hx = "0123456789abcdef"
	out := []byte{}
	for i, x := range b {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out = append(out, '-')
		}
		out = append(out, hx[x>>4], hx[x&15])
	}
	return string(out)
}

// SetLeaf replaces the certificate used for a serial number.
func (s *Server) SetLeaf(serial string, l *smartidtest.Leaf) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.leaves[serial] = l
}
