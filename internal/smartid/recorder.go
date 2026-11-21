package smartid

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Exchange is one recorded RP API request/response pair (fixtures only).
type Exchange struct {
	Name     string          `json:"name"`
	Method   string          `json:"method"`
	Path     string          `json:"path"`
	Status   int             `json:"status"`
	Request  json.RawMessage `json:"request,omitempty"`
	Response json.RawMessage `json:"response,omitempty"`
}

// Recorder captures exchanges for the spike's fixture output. A nil Recorder
// records nothing.
type Recorder struct {
	mu        sync.Mutex
	Exchanges []Exchange
}

func (r *Recorder) record(name, method, path string, status int, req, resp []byte) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	x := Exchange{Name: name, Method: method, Path: path, Status: status}
	if json.Valid(req) {
		x.Request = append(json.RawMessage(nil), req...)
	}
	if json.Valid(resp) {
		x.Response = append(json.RawMessage(nil), resp...)
	}
	r.Exchanges = append(r.Exchanges, x)
}

// MockSubmitDeviceLink posts a device link to the demo environment's
// automated testing interface (sid.demo.sk.ee/mock, spec "Smart-ID Automated
// Testing Interface" 1.1.0), which simulates the phone for SK's published
// test document numbers. Demo only.
func MockSubmitDeviceLink(ctx context.Context, mockBase, documentNumber, deviceLink string, rec *Recorder) error {
	return MockSubmit(ctx, mockBase, MockDeviceLink{DocumentNumber: documentNumber, DeviceLink: deviceLink}, rec)
}

// MockDeviceLink is the automated testing interface request body.
type MockDeviceLink struct {
	DocumentNumber            string `json:"documentNumber"`
	DeviceLink                string `json:"deviceLink"`
	BrowserCookie             string `json:"browserCookie,omitempty"`
	DisableCallbackGetRequest bool   `json:"disableCallbackGetRequest,omitempty"`
}

// mockDestination accepts the published demo endpoint or a literal loopback
// address for local test servers. It returns whether the address is loopback.
func mockDestination(raw string) (*url.URL, bool, error) {
	invalid := errors.New("smartid: automated testing interface is demo-only")
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#") {
		return nil, false, invalid
	}
	if raw == "https://sid.demo.sk.ee/mock" {
		return u, false, nil
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, false, invalid
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return nil, false, invalid
	}
	authority := host
	if strings.Contains(host, ":") {
		authority = "[" + host + "]"
	}
	if port := u.Port(); port != "" {
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 {
			return nil, false, invalid
		}
		authority += ":" + port
	}
	if u.Host != authority {
		return nil, false, invalid
	}
	return u, true, nil
}

func mockClient(timeout time.Duration, loopback bool) *http.Client {
	c := &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if loopback {
		// A local mock must never receive sensitive data through a proxy.
		c.Transport = &http.Transport{}
	}
	return c
}

// MockSubmit posts a device link to the automated testing interface.
func MockSubmit(ctx context.Context, mockBase string, m MockDeviceLink, rec *Recorder) error {
	u, loopback, err := mockDestination(mockBase)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(m)
	u.Path = strings.TrimRight(u.Path, "/") + "/device-link"
	u.RawPath = ""
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	c := mockClient(30*time.Second, loopback)
	defer c.CloseIdleConnections()
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	rec.record("mock-device-link", http.MethodPost, "/mock/device-link", resp.StatusCode, body, data)
	if resp.StatusCode/100 != 2 {
		return &HTTPError{Status: resp.StatusCode}
	}
	return nil
}

// MockCallbackURL long-polls the automated testing interface for the
// callback URL the app would open (only when DisableCallbackGetRequest).
func MockCallbackURL(ctx context.Context, mockBase, sessionToken string, rec *Recorder) (string, error) {
	u, loopback, err := mockDestination(mockBase)
	if err != nil {
		return "", err
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/device-link/callback-url/" + sessionToken
	u.RawPath = ""
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	c := mockClient(70*time.Second, loopback)
	defer c.CloseIdleConnections()
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	rec.record("mock-callback-url", http.MethodGet, "/mock/device-link/callback-url/{sessionToken}", resp.StatusCode, nil, data)
	if resp.StatusCode != http.StatusOK {
		return "", &HTTPError{Status: resp.StatusCode}
	}
	var out struct {
		CallbackURL string `json:"callbackUrl"`
	}
	if err := json.Unmarshal(data, &out); err != nil || out.CallbackURL == "" {
		return "", errors.New("smartid: malformed callback-url response")
	}
	return out.CallbackURL, nil
}

// SessionToken exposes the token for the demo automated testing interface.
func (s *Session) SessionToken() string { return s.token }
