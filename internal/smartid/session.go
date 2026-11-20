package smartid

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"
)

// Demo environment constants from the pinned environments page
// (spec pin smartid-environments).
const (
	DemoRPUUID  = "00000000-0000-4000-8000-000000000000"
	DemoRPName  = "DEMO"
	SchemeDemo  = "smart-id-demo"
	SchemeLive  = "smart-id"
	DemoBaseURL = "https://sid.demo.sk.ee/smart-id-rp"
	LiveBaseURL = "https://rp-api.smart-id.com"
)

// Flow types the bridge can offer (signature.flowType values).
const (
	FlowQR           = "QR"
	FlowWeb2App      = "Web2App"
	FlowNotification = "Notification"
)

// Certificate levels, ordered.
const (
	LevelAdvanced  = "ADVANCED"
	LevelQualified = "QUALIFIED"
)

func levelRank(l string) int {
	switch l {
	case LevelAdvanced:
		return 1
	case LevelQualified:
		return 2
	}
	return 0
}

// Session is the RP-side state of one upstream authentication session. Its
// secrets are held as byte slices and cleared by Destroy. sessionSecret never
// leaves the backend.
type Session struct {
	ID                 string
	Flow               string // offered flow: QR, Web2App or Notification
	InitialCallbackURL string // empty for QR and Notification
	Interactions       string // exact Base64 string sent at creation
	Lang               string // ISO 639-2 for the fallback page
	ExpectedIdentity   string // ETSI semantics id or document number (notification only)
	VC                 string // notification verification code shown to the user

	token       string
	secret      []byte
	linkBase    string
	rpChallenge []byte
	created     time.Time // includes Go's monotonic reading
	scheme      string
	rpName      string
}

// RPChallengeB64 returns the challenge exactly as sent (standard Base64).
func (s *Session) RPChallengeB64() string { return base64.StdEncoding.EncodeToString(s.rpChallenge) }

// Created returns the time the session-creation response arrived.
func (s *Session) Created() time.Time { return s.created }

// Destroy zeroes the session secret and challenge (best effort under Go's GC).
func (s *Session) Destroy() {
	clear(s.secret)
	clear(s.rpChallenge)
	s.secret, s.rpChallenge, s.token = nil, nil, ""
}

// ErrDestroyed is returned when a destroyed session is used.
var ErrDestroyed = errors.New("smartid: session destroyed")

// QRLink returns the dynamic QR device link for now. It changes every second
// because elapsedSeconds is part of the authenticated link.
func (s *Session) QRLink(now time.Time) (string, error) {
	if s.Flow != FlowQR {
		return "", errors.New("smartid: QR link requested for non-QR flow")
	}
	el := int(now.Sub(s.created) / time.Second)
	if el < 0 {
		el = 0
	}
	return s.link("QR", strconv.Itoa(el))
}

// Web2AppLink returns the static same-device link.
func (s *Session) Web2AppLink() (string, error) {
	if s.Flow != FlowWeb2App {
		return "", errors.New("smartid: Web2App link requested for non-Web2App flow")
	}
	return s.link("Web2App", "")
}

func (s *Session) link(kind, elapsed string) (string, error) {
	if s.secret == nil {
		return "", ErrDestroyed
	}
	var b strings.Builder
	b.WriteString(s.linkBase)
	b.WriteString("?deviceLinkType=")
	b.WriteString(kind)
	if elapsed != "" {
		b.WriteString("&elapsedSeconds=")
		b.WriteString(elapsed)
	}
	b.WriteString("&sessionToken=")
	b.WriteString(s.token)
	b.WriteString("&sessionType=auth&version=1.0&lang=")
	b.WriteString(s.Lang)
	unprotected := b.String()
	code := AuthCode(s.secret, AuthCodePayload(s.scheme, s.RPChallengeB64(), s.rpName, "", s.Interactions, s.InitialCallbackURL, unprotected))
	return unprotected + "&authCode=" + code, nil
}

// AuthCodePayload assembles the device-link authCode input for an
// authentication session (AUTHCODE page, pin smartid-rp-api-v3-authcode).
func AuthCodePayload(scheme, rpChallengeB64, rpName, brokeredRPName, interactions, callbackURL, unprotectedLink string) []byte {
	return []byte(strings.Join([]string{scheme, "ACSP_V2", rpChallengeB64,
		b64(rpName), b64(brokeredRPName), interactions, callbackURL, unprotectedLink}, "|"))
}

// AuthCode is Base64URL(HMAC-SHA256(sessionSecret, payload)) without padding.
func AuthCode(secret, payload []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write(payload)
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// SecretDigestMatches reports whether a Web2App callback sessionSecretDigest
// equals Base64URL(SHA-256(sessionSecret)), in constant time.
func (s *Session) SecretDigestMatches(digest string) bool {
	if s.secret == nil {
		return false
	}
	sum := sha256.Sum256(s.secret)
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	got := strings.TrimRight(digest, "=")
	return subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}

// NotificationVC computes the 4-digit verification code for a notification
// authentication: SHA-256 of the raw rpChallenge, last two bytes as a
// big-endian integer, modulo 10000, zero-padded (NOTIF page).
func NotificationVC(rpChallenge []byte) string {
	sum := sha256.Sum256(rpChallenge)
	n := (int(sum[30])<<8 | int(sum[31])) % 10000
	s := strconv.Itoa(n)
	return strings.Repeat("0", 4-len(s)) + s
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
