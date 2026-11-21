package smartidtest

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Default scenario table: SK's published demo test document numbers and the
// endResult each produces (test_accounts page, 2026-11-20).
var DefaultScenarios = map[string]string{
	"PNOEE-40404040009-MOCK-Q":  "OK",
	"PNOEE-40504040001-MOCK-Q":  "OK",
	"PNOLV-040404-10003-MOCK-Q": "OK",
	"PNOLT-40404040009-MOCK-Q":  "OK",
	"PNOEE-30403039917-MOCK-Q":  "USER_REFUSED",
	"PNOEE-30403039928-MOCK-Q":  "USER_REFUSED_INTERACTION",
	"PNOEE-30403039972-MOCK-Q":  "WRONG_VC",
	"PNOEE-30403039983-MOCK-Q":  "TIMEOUT",
}

// Server is a synthetic RP API v3 plus automated testing interface.
type Server struct {
	PKI         *PKI
	Scheme      string            // default smart-id-demo
	RPUUID      string            // accepted relying party UUID
	Scenarios   map[string]string // document number → endResult
	AutoResolve string            // if set, QR and Web2App sessions resolve with this document on first poll
	MaxWait     time.Duration     // long-poll cap, default 100ms
	// Mutate, when set, may rewrite a completed status before it is served.
	Mutate func(status map[string]any)

	mu       sync.Mutex
	sessions map[string]*fakeSession
	byToken  map[string]*fakeSession
	leaves   map[string]*Leaf

	// FailPolls makes every session poll answer HTTP 500.
	FailPolls atomic.Bool

	Polls       atomic.Int64
	Creates     atomic.Int64
	inflight    atomic.Int64
	MaxInflight atomic.Int64
}

type fakeSession struct {
	id, token   string
	secret      []byte
	req         authReq
	flow        string // QR, Web2App, Notification
	target      string // notification semantics id or document number
	done        chan struct{}
	status      map[string]any
	callbackURL string
	resolved    bool
	created     time.Time
	kind        string // "" authentication, "certchoice" or "sign"
	digest      []byte
	signReq     signReq
}

type authReq struct {
	RPUUID             string  `json:"relyingPartyUUID"`
	RPName             string  `json:"relyingPartyName"`
	InitialCallbackURL *string `json:"initialCallbackUrl"`
	CertificateLevel   string  `json:"certificateLevel"`
	SignatureProtocol  string  `json:"signatureProtocol"`
	Params             struct {
		RPChallenge        string            `json:"rpChallenge"`
		SignatureAlgorithm string            `json:"signatureAlgorithm"`
		AlgParams          map[string]string `json:"signatureAlgorithmParameters"`
	} `json:"signatureProtocolParameters"`
	Interactions string `json:"interactions"`
}

// NewServer returns a server with a fresh PKI and default scenarios.
func NewServer() *Server {
	return &Server{PKI: NewPKI("eidbridge"), Scheme: "smart-id-demo", RPUUID: "00000000-0000-4000-8000-000000000000",
		Scenarios: DefaultScenarios, MaxWait: 100 * time.Millisecond,
		sessions: map[string]*fakeSession{}, byToken: map[string]*fakeSession{}, leaves: map[string]*Leaf{}}
}

func (s *Server) init() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions == nil {
		s.sessions, s.byToken, s.leaves = map[string]*fakeSession{}, map[string]*fakeSession{}, map[string]*Leaf{}
	}
}

var (
	reControl   = regexp.MustCompile(`^/_mock/sessions/([0-9a-f-]{36})/(complete|refuse|timeout|wrong-vc)$`)
	reB64       = regexp.MustCompile(`^[a-zA-Z0-9+/]+={0,2}$`)
	reSessionID = regexp.MustCompile(`^/v3/session/([0-9a-f-]{36})$`)
)

// ServeHTTP implements the subset of the RP API the bridge uses.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.init()
	p := strings.TrimPrefix(r.URL.Path, "/smart-id-rp")
	switch {
	case r.Method == http.MethodPost && p == "/v3/authentication/device-link/anonymous":
		s.create(w, r, "")
	case r.Method == http.MethodPost && strings.HasPrefix(p, "/v3/authentication/notification/etsi/"):
		s.create(w, r, strings.TrimPrefix(p, "/v3/authentication/notification/etsi/"))
	case r.Method == http.MethodPost && strings.HasPrefix(p, "/v3/authentication/notification/document/"):
		s.create(w, r, strings.TrimPrefix(p, "/v3/authentication/notification/document/"))
	case r.Method == http.MethodPost && strings.HasPrefix(p, "/v3/signature/"):
		kind, target, ok := signTarget(p)
		if !ok {
			problem(w, http.StatusNotFound, "Not Found")
			return
		}
		s.signCreate(w, r, kind, target)
	case r.Method == http.MethodGet && reSessionID.MatchString(p):
		s.poll(w, r, reSessionID.FindStringSubmatch(p)[1])
	case r.Method == http.MethodPost && strings.HasSuffix(p, "/mock/device-link"):
		s.deviceLink(w, r)
	case r.Method == http.MethodGet && strings.Contains(p, "/mock/device-link/callback-url/"):
		s.callbackURL(w, p[strings.LastIndex(p, "/")+1:])
	case r.Method == http.MethodGet && r.URL.Path == "/_mock/sessions":
		s.listSessions(w)
	case r.Method == http.MethodPost && reControl.MatchString(r.URL.Path):
		m := reControl.FindStringSubmatch(r.URL.Path)
		s.control(w, m[1], m[2], r.URL.Query().Get("document"))
	default:
		problem(w, http.StatusNotFound, "Not Found")
	}
}

func problem(w http.ResponseWriter, code int, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]any{"status": code, "title": http.StatusText(code), "detail": detail})
}

func randB64(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func randAlnum(n int) string {
	const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = a[int(b[i])%len(a)]
	}
	return string(b)
}

func uuid() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := "0123456789abcdef"
	out := make([]byte, 0, 36)
	for i, x := range b {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out = append(out, '-')
		}
		out = append(out, h[x>>4], h[x&15])
	}
	return string(out)
}

func (s *Server) create(w http.ResponseWriter, r *http.Request, target string) {
	var req authReq
	body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err := json.Unmarshal(body, &req); err != nil {
		problem(w, 400, "malformed JSON")
		return
	}
	if req.RPUUID != s.RPUUID {
		problem(w, 401, "unknown relying party")
		return
	}
	ch := req.Params.RPChallenge
	if req.RPName == "" || req.SignatureProtocol != "ACSP_V2" || len(ch) < 44 || len(ch) > 88 || !reB64.MatchString(ch) ||
		req.Interactions == "" || !reB64.MatchString(req.Interactions) || req.Params.SignatureAlgorithm != "rsassa-pss" {
		problem(w, 400, "Invalid request parameters found")
		return
	}
	fs := &fakeSession{id: uuid(), req: req, target: target, done: make(chan struct{}), created: time.Now()}
	if target != "" {
		fs.flow = "Notification"
	} else {
		if req.InitialCallbackURL == nil {
			fs.flow = "QR"
		} else if *req.InitialCallbackURL == "" {
			problem(w, 400, "Invalid initialCallbackUrl: The callback URL value must not be blank")
			return
		} else if !strings.HasPrefix(*req.InitialCallbackURL, "https://") || len(*req.InitialCallbackURL) > 1800 {
			problem(w, 400, "Invalid initialCallbackUrl")
			return
		} else {
			fs.flow = "Web2App"
		}
		fs.token = randAlnum(24)
		raw := make([]byte, 18)
		rand.Read(raw)
		fs.secret = raw
	}
	s.Creates.Add(1)
	s.mu.Lock()
	s.sessions[fs.id] = fs
	if fs.token != "" {
		s.byToken[fs.token] = fs
	}
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if fs.flow == "Notification" {
		json.NewEncoder(w).Encode(map[string]string{"sessionID": fs.id})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"sessionID": fs.id, "sessionToken": fs.token,
		"sessionSecret": base64.StdEncoding.EncodeToString(fs.secret), "deviceLinkBase": "https://sid.demo.sk.ee/device-link"})
}

// Leaf returns (and caches) the certificate for a semantics identifier.
func (s *Server) Leaf(serial string) *Leaf {
	s.mu.Lock()
	defer s.mu.Unlock()
	if l, ok := s.leaves[serial]; ok {
		return l
	}
	l := s.PKI.NewLeaf(LeafOptions{SerialNumber: serial})
	s.leaves[serial] = l
	return l
}

func docSerial(doc string) string {
	// PNOEE-40404040009-MOCK-Q → PNOEE-40404040009; PNOLV-040404-10003-MOCK-Q → PNOLV-040404-10003
	parts := strings.Split(doc, "-")
	if len(parts) >= 4 && len(parts[1]) == 6 {
		return strings.Join(parts[:3], "-")
	}
	if len(parts) >= 2 {
		return parts[0] + "-" + parts[1]
	}
	return doc
}

// resolve completes a session for a document number.
func (s *Server) resolve(fs *fakeSession, doc string) {
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
	cbu := ""
	if end == "OK" {
		serial := docSerial(doc)
		leaf := s.Leaf(serial)
		verifier := strings.TrimRight(base64.RawURLEncoding.EncodeToString([]byte(randAlnum(32))), "=")
		uc := sha256.Sum256([]byte(verifier))
		userChallenge := base64.RawURLEncoding.EncodeToString(uc[:])
		serverRandom := randB64(18)
		cb := ""
		if fs.req.InitialCallbackURL != nil {
			cb = *fs.req.InitialCallbackURL
		}
		ih := sha256.Sum256([]byte(fs.req.Interactions))
		msg := strings.Join([]string{s.Scheme, "ACSP_V2", serverRandom, fs.req.Params.RPChallenge, userChallenge,
			b64(fs.req.RPName), b64(""), base64.StdEncoding.EncodeToString(ih[:]), "displayTextAndPIN", cb, fs.flow}, "|")
		d := sha512.Sum512([]byte(msg))
		sig, _ := rsa.SignPSS(rand.Reader, leaf.Key.(*rsa.PrivateKey), crypto.SHA512, d[:], &rsa.PSSOptions{SaltLength: 64})
		st["result"] = map[string]any{"endResult": "OK", "documentNumber": doc}
		st["signatureProtocol"] = "ACSP_V2"
		st["signature"] = map[string]any{"value": base64.StdEncoding.EncodeToString(sig), "serverRandom": serverRandom,
			"userChallenge": userChallenge, "flowType": fs.flow, "signatureAlgorithm": "rsassa-pss",
			"signatureAlgorithmParameters": map[string]any{"hashAlgorithm": "SHA-512",
				"maskGenAlgorithm": map[string]any{"algorithm": "id-mgf1", "parameters": map[string]any{"hashAlgorithm": "SHA-512"}},
				"saltLength":       64, "trailerField": "0xbc"}}
		st["cert"] = map[string]any{"value": base64.StdEncoding.EncodeToString(leaf.Cert.Raw), "certificateLevel": "QUALIFIED"}
		st["interactionTypeUsed"] = "displayTextAndPIN"
		if fs.flow == "Web2App" {
			sd := sha256.Sum256(fs.secret)
			cbu = cb + "&sessionSecretDigest=" + base64.RawURLEncoding.EncodeToString(sd[:]) + "&userChallengeVerifier=" + verifier
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
	fs.callbackURL = cbu
	s.mu.Unlock()
	close(fs.done)
}

func b64(x string) string { return base64.StdEncoding.EncodeToString([]byte(x)) }

func (s *Server) poll(w http.ResponseWriter, r *http.Request, id string) {
	n := s.inflight.Add(1)
	defer s.inflight.Add(-1)
	for {
		m := s.MaxInflight.Load()
		if n <= m || s.MaxInflight.CompareAndSwap(m, n) {
			break
		}
	}
	s.Polls.Add(1)
	if s.FailPolls.Load() {
		problem(w, 500, "induced failure")
		return
	}
	s.mu.Lock()
	fs := s.sessions[id]
	s.mu.Unlock()
	if fs == nil {
		problem(w, 404, "session does not exist or has expired")
		return
	}
	s.mu.Lock()
	resolved := fs.resolved
	s.mu.Unlock()
	if !resolved {
		if fs.kind != "" {
			doc := fs.target
			if _, ok := s.Scenarios[doc]; !ok && fs.kind == "certchoice" {
				doc += "-MOCK-Q"
			}
			go s.resolveSign(fs, doc)
		} else if fs.flow == "Notification" {
			doc := fs.target
			if _, ok := s.Scenarios[doc]; !ok {
				doc += "-MOCK-Q"
			}
			go s.resolve(fs, doc)
		} else if s.AutoResolve != "" {
			go s.resolve(fs, s.AutoResolve)
		}
	}
	wait := s.MaxWait
	if ms, err := strconv.Atoi(r.URL.Query().Get("timeoutMs")); err == nil && time.Duration(ms)*time.Millisecond < wait {
		wait = time.Duration(ms) * time.Millisecond
	}
	select {
	case <-fs.done:
	case <-time.After(wait):
	case <-r.Context().Done():
		return
	}
	w.Header().Set("Content-Type", "application/json")
	s.mu.Lock()
	st := fs.status
	s.mu.Unlock()
	if st == nil {
		json.NewEncoder(w).Encode(map[string]any{"state": "RUNNING"})
		return
	}
	json.NewEncoder(w).Encode(st)
}

func (s *Server) deviceLink(w http.ResponseWriter, r *http.Request) {
	var m struct {
		DocumentNumber string `json:"documentNumber"`
		DeviceLink     string `json:"deviceLink"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&m); err != nil || m.DocumentNumber == "" {
		http.Error(w, `{"message":"invalid request"}`, 400)
		return
	}
	u, err := url.Parse(m.DeviceLink)
	if err != nil {
		http.Error(w, `{"message":"invalid device link"}`, 400)
		return
	}
	q := u.Query()
	s.mu.Lock()
	fs := s.byToken[q.Get("sessionToken")]
	s.mu.Unlock()
	s.mu.Lock()
	done := fs != nil && fs.resolved
	s.mu.Unlock()
	if fs == nil || done {
		http.Error(w, `{"message":"unknown or finished session"}`, 400)
		return
	}
	// Recompute authCode over the unprotected link exactly as received.
	i := strings.LastIndex(m.DeviceLink, "&authCode=")
	if i < 0 {
		http.Error(w, `{"message":"missing authCode"}`, 400)
		return
	}
	unprotected, code := m.DeviceLink[:i], m.DeviceLink[i+len("&authCode="):]
	cb := ""
	if fs.req.InitialCallbackURL != nil {
		cb = *fs.req.InitialCallbackURL
	}
	payload := strings.Join([]string{s.Scheme, "ACSP_V2", fs.req.Params.RPChallenge, b64(fs.req.RPName), b64(""), fs.req.Interactions, cb, unprotected}, "|")
	mac := hmac.New(sha256.New, fs.secret)
	mac.Write([]byte(payload))
	if !hmac.Equal([]byte(base64.RawURLEncoding.EncodeToString(mac.Sum(nil))), []byte(code)) {
		http.Error(w, `{"message":"Invalid device link"}`, 400)
		return
	}
	if q.Get("deviceLinkType") != fs.flow {
		http.Error(w, `{"message":"device link type does not match flow"}`, 400)
		return
	}
	go s.resolve(fs, m.DocumentNumber)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) callbackURL(w http.ResponseWriter, token string) {
	s.mu.Lock()
	fs := s.byToken[token]
	s.mu.Unlock()
	if fs == nil {
		http.Error(w, `{"message":"not found"}`, 404)
		return
	}
	select {
	case <-fs.done:
	case <-time.After(2 * time.Second):
	}
	s.mu.Lock()
	cbu := fs.callbackURL
	s.mu.Unlock()
	if cbu == "" {
		http.Error(w, `{"message":"not found"}`, 404)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"callbackUrl": cbu})
}

// Expire deletes a session so later polls get 404.
func (s *Server) Expire(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

// SetMutate replaces the status mutation hook safely.
func (s *Server) SetMutate(f func(map[string]any)) {
	s.init()
	s.mu.Lock()
	s.Mutate = f
	s.mu.Unlock()
}

// ControlDocuments maps control actions to the default scenario document.
var ControlDocuments = map[string]string{"complete": "PNOEE-40404040009-MOCK-Q", "refuse": "PNOEE-30403039917-MOCK-Q",
	"timeout": "PNOEE-30403039983-MOCK-Q", "wrong-vc": "PNOEE-30403039972-MOCK-Q"}

// control resolves one session (POST /_mock/sessions/{id}/{action}).
// complete accepts ?document= to choose the identity; it must be a
// scenario with result OK.
func (s *Server) control(w http.ResponseWriter, id, action, doc string) {
	s.mu.Lock()
	fs := s.sessions[id]
	s.mu.Unlock()
	if fs == nil {
		problem(w, http.StatusNotFound, "no such session")
		return
	}
	if doc == "" || action != "complete" {
		doc = ControlDocuments[action]
	}
	if action == "complete" && s.Scenarios[doc] != "OK" {
		problem(w, http.StatusBadRequest, "document is not an OK scenario")
		return
	}
	s.resolve(fs, doc)
	w.WriteHeader(http.StatusNoContent)
}

// listSessions returns the ids of sessions not yet resolved.
func (s *Server) listSessions(w http.ResponseWriter) {
	s.mu.Lock()
	ids := []string{}
	for id, fs := range s.sessions {
		if !fs.resolved {
			ids = append(ids, id)
		}
	}
	s.mu.Unlock()
	sort.Strings(ids)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"pending": ids})
}
