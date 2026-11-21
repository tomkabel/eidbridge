package smartidtest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// Signature sessions (Story 8.1): certificate-choice by ETSI identifier and
// RAW_DIGEST_SIGNATURE by document number, written from the pinned
// RP-API_V3.yml. Signing certificates are separate synthetic leaves with
// nonRepudiation only and their own RSA-3072 key.

type signReq struct {
	RPUUID            string `json:"relyingPartyUUID"`
	RPName            string `json:"relyingPartyName"`
	CertificateLevel  string `json:"certificateLevel"`
	SignatureProtocol string `json:"signatureProtocol"`
	Params            struct {
		Digest             string `json:"digest"`
		SignatureAlgorithm string `json:"signatureAlgorithm"`
		AlgParams          *struct {
			HashAlgorithm string `json:"hashAlgorithm"`
		} `json:"signatureAlgorithmParameters"`
	} `json:"signatureProtocolParameters"`
	Interactions string `json:"interactions"`
}

// SignLeaf returns (and caches) the signing certificate for a serial.
func (s *Server) SignLeaf(serial string) *Leaf {
	s.mu.Lock()
	defer s.mu.Unlock()
	if l, ok := s.leaves["sign:"+serial]; ok {
		return l
	}
	l := s.PKI.NewLeaf(LeafOptions{SerialNumber: serial, NoAuthEKU: true, KeyUsage: x509.KeyUsageContentCommitment, RSABits: 3072})
	s.leaves["sign:"+serial] = l
	return l
}

func (s *Server) signCreate(w http.ResponseWriter, r *http.Request, kind, target string) {
	var req signReq
	body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if json.Unmarshal(body, &req) != nil {
		problem(w, 400, "malformed JSON")
		return
	}
	if req.RPUUID != s.RPUUID {
		problem(w, 401, "unknown relying party")
		return
	}
	if req.RPName == "" {
		problem(w, 400, "Invalid request parameters found")
		return
	}
	fs := &fakeSession{id: uuid(), target: target, flow: "Notification", kind: kind, done: make(chan struct{}), created: time.Now()}
	if kind == "sign" {
		p := req.Params
		d, err := base64.StdEncoding.DecodeString(p.Digest)
		okAlg := p.SignatureAlgorithm == "rsassa-pss" && p.AlgParams != nil && signHash[p.AlgParams.HashAlgorithm] != 0 ||
			signHash[pkcs1Hash[p.SignatureAlgorithm]] != 0
		if req.SignatureProtocol != "RAW_DIGEST_SIGNATURE" || err != nil || len(p.Digest) < 44 || len(p.Digest) > 88 ||
			!reB64.MatchString(p.Digest) || !okAlg || req.Interactions == "" || !reB64.MatchString(req.Interactions) {
			problem(w, 400, "Invalid request parameters found")
			return
		}
		fs.digest = d
		fs.signReq = req
	}
	s.Creates.Add(1)
	s.mu.Lock()
	s.sessions[fs.id] = fs
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if kind == "sign" {
		json.NewEncoder(w).Encode(map[string]any{"sessionID": fs.id, "vc": map[string]string{"type": "numeric4", "value": "4927"}})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"sessionID": fs.id})
}

var (
	signHash  = map[string]crypto.Hash{"SHA-256": crypto.SHA256, "SHA-384": crypto.SHA384, "SHA-512": crypto.SHA512}
	pkcs1Hash = map[string]string{"sha256WithRSAEncryption": "SHA-256", "sha384WithRSAEncryption": "SHA-384", "sha512WithRSAEncryption": "SHA-512"}
)

// resolveSign completes a certificate-choice or signature session.
func (s *Server) resolveSign(fs *fakeSession, doc string) {
	s.mu.Lock()
	if fs.resolved {
		s.mu.Unlock()
		return
	}
	fs.resolved = true
	s.mu.Unlock()
	end, ok := s.Scenarios[doc]
	if !ok {
		end = "DOCUMENT_UNUSABLE"
	}
	st := map[string]any{"state": "COMPLETE", "result": map[string]any{"endResult": end}}
	if end == "OK" {
		leaf := s.SignLeaf(docSerial(doc))
		st["result"] = map[string]any{"endResult": "OK", "documentNumber": doc}
		st["cert"] = map[string]any{"value": base64.StdEncoding.EncodeToString(leaf.Cert.Raw), "certificateLevel": "QUALIFIED"}
		if fs.kind == "certchoice" {
			st["signature"] = map[string]any{"flowType": "Notification"}
		} else {
			p := fs.signReq.Params
			var sig []byte
			var err error
			sigObj := map[string]any{"flowType": "Notification", "signatureAlgorithm": p.SignatureAlgorithm}
			if p.SignatureAlgorithm == "rsassa-pss" {
				h := signHash[p.AlgParams.HashAlgorithm]
				sig, err = rsa.SignPSS(rand.Reader, leaf.Key.(*rsa.PrivateKey), h, fs.digest, &rsa.PSSOptions{SaltLength: h.Size(), Hash: h})
				sigObj["signatureAlgorithmParameters"] = map[string]any{"hashAlgorithm": p.AlgParams.HashAlgorithm,
					"maskGenAlgorithm": map[string]any{"algorithm": "id-mgf1", "parameters": map[string]any{"hashAlgorithm": p.AlgParams.HashAlgorithm}},
					"saltLength":       h.Size(), "trailerField": "0xbc"}
			} else {
				sig, err = rsa.SignPKCS1v15(rand.Reader, leaf.Key.(*rsa.PrivateKey), signHash[pkcs1Hash[p.SignatureAlgorithm]], fs.digest)
			}
			if err != nil { // digest length does not match the hash
				st = map[string]any{"state": "COMPLETE", "result": map[string]any{"endResult": "PROTOCOL_FAILURE"}}
			} else {
				sigObj["value"] = base64.StdEncoding.EncodeToString(sig)
				st["signatureProtocol"] = "RAW_DIGEST_SIGNATURE"
				st["signature"] = sigObj
				st["interactionTypeUsed"] = firstInteraction(fs.signReq.Interactions)
			}
		}
	}
	s.mu.Lock()
	mutate := s.Mutate
	s.mu.Unlock()
	if mutate != nil {
		mutate(st)
	}
	s.mu.Lock()
	fs.status = st
	s.mu.Unlock()
	close(fs.done)
}

func firstInteraction(b64s string) string {
	b, _ := base64.StdEncoding.DecodeString(b64s)
	var list []struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(b, &list) != nil || len(list) == 0 {
		return ""
	}
	return list[0].Type
}

func signTarget(p string) (kind, target string, ok bool) {
	for prefix, k := range map[string]string{
		"/v3/signature/certificate-choice/notification/etsi/": "certchoice",
		"/v3/signature/notification/document/":                "sign",
	} {
		if strings.HasPrefix(p, prefix) {
			return k, strings.TrimPrefix(p, prefix), true
		}
	}
	return "", "", false
}
