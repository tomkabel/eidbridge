package web

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

const cookiePrefix = "__Host-eidb-"

// cookieValue is the fixed-schema flow cookie (ADR-010). None of it is
// secret or personal except the random binding token, which is checked in
// constant time against the stored hash.
type cookieValue struct {
	B string `json:"b"` // binding token (256-bit, base64url)
	T int64  `json:"t"` // creation (unix seconds)
	C string `json:"c"` // client_id
	R string `json:"r"` // redirect_uri
	S string `json:"s"` // state
}

const maxCookie = 1024

func encodeCookie(v cookieValue) (string, bool) {
	b, _ := json.Marshal(v)
	s := base64.RawURLEncoding.EncodeToString(b)
	return s, len(s) <= maxCookie
}

func decodeCookie(s string) (cookieValue, bool) {
	var v cookieValue
	if len(s) > maxCookie {
		return v, false
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || json.Unmarshal(b, &v) != nil || v.B == "" {
		return v, false
	}
	return v, true
}

func setFlowCookie(w http.ResponseWriter, flowID, value string, remaining time.Duration) {
	secs := int(remaining / time.Second)
	if secs < 1 {
		secs = 1
	}
	http.SetCookie(w, &http.Cookie{Name: cookiePrefix + flowID, Value: value, Path: "/", MaxAge: secs,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

func clearFlowCookie(w http.ResponseWriter, flowID string) {
	http.SetCookie(w, &http.Cookie{Name: cookiePrefix + flowID, Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

// flowCookies returns the browser's flow cookies by flow ID.
func flowCookies(r *http.Request) map[string]cookieValue {
	out := map[string]cookieValue{}
	for _, c := range r.Cookies() {
		if id, ok := strings.CutPrefix(c.Name, cookiePrefix); ok {
			if v, ok := decodeCookie(c.Value); ok {
				out[id] = v
			}
		}
	}
	return out
}
