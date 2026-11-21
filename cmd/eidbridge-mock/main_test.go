package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/smartid"
)

func startMock(t *testing.T, extra ...string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	ready := make(chan string, 1)
	go run(append([]string{"--listen", "127.0.0.1:0", "--ca-out", ca}, extra...), io.Discard, io.Discard, ready)
	select {
	case addr := <-ready:
		return "http://" + addr, ca
	case <-time.After(5 * time.Second):
		t.Fatal("mock did not start")
	}
	return "", ""
}

func client(t *testing.T, base, ca string) *smartid.Client {
	t.Helper()
	dir := filepath.Dir(ca)
	ts, err := smartid.LoadCADir(dir)
	if err != nil {
		t.Fatal(err)
	}
	c, err := smartid.NewClient(smartid.Config{BaseURL: base + "/smart-id-rp", RPUUID: smartid.DemoRPUUID, RPName: smartid.DemoRPName,
		SchemeName: smartid.SchemeDemo, HTTP: http.DefaultClient, Trust: ts, MinCertLevel: smartid.LevelQualified,
		Status: smartid.NoStatusCheck{}, PolicyOIDs: smartid.DemoPolicyOIDs})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Story 7.4 AC: every scenario (complete, refuse, timeout, wrong VC) is
// driven through the control API and verified by a real RP API client
// trusting only the --ca-out bundle.
func TestControlScenarios(t *testing.T) {
	base, ca := startMock(t)
	c := client(t, base, ca)
	for action, want := range map[string]string{"complete": "", "refuse": "refused", "timeout": "expired", "wrong-vc": "wrong_code"} {
		s, err := c.StartDeviceLink(context.Background(), smartid.DeviceLinkRequest{Flow: smartid.FlowQR, DisplayText60: "Log in", Lang: "eng"})
		if err != nil {
			t.Fatal(err)
		}
		r, _ := http.Get(base + "/_mock/sessions")
		var list struct{ Pending []string }
		json.NewDecoder(r.Body).Decode(&list)
		r.Body.Close()
		found := false
		for _, id := range list.Pending {
			found = found || id == s.ID
		}
		if !found {
			t.Fatalf("%s: session not listed", action)
		}
		r, err = http.Post(base+"/_mock/sessions/"+s.ID+"/"+action, "", nil)
		if err != nil || r.StatusCode != http.StatusNoContent {
			t.Fatalf("%s: control %v %v", action, err, r.StatusCode)
		}
		st, err := c.Poll(context.Background(), s.ID, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_, verr := c.Verify(s, st, nil)
		got := ""
		if verr != nil {
			got = smartid.ReasonOf(verr)
		}
		if got != want {
			t.Errorf("%s: reason %q, want %q (%v)", action, got, want, verr)
		}
	}
	if r, _ := http.Post(base+"/_mock/sessions/00000000-0000-4000-8000-000000000000/complete", "", nil); r.StatusCode != 404 {
		t.Fatal("unknown session accepted")
	}
}

func TestScenarioFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "s.yaml")
	os.WriteFile(f, []byte("PNOEE-50001029996-MOCK-Q: OK\n"), 0o644)
	base, ca := startMock(t, "--scenario", f)
	c := client(t, base, ca)
	s, _ := c.StartDeviceLink(context.Background(), smartid.DeviceLinkRequest{Flow: smartid.FlowQR, DisplayText60: "Log in", Lang: "eng"})
	r, _ := http.Post(base+"/_mock/sessions/"+s.ID+"/complete?document=PNOEE-50001029996-MOCK-Q", "", nil)
	if r.StatusCode != http.StatusNoContent {
		t.Fatalf("scenario identity refused: %d", r.StatusCode)
	}
	st, _ := c.Poll(context.Background(), s.ID, time.Second)
	if id, err := c.Verify(s, st, nil); err != nil || id.Code != "50001029996" {
		t.Fatalf("%+v %v", id, err)
	}
}

// Story 7.4 AC: refuses a non-loopback address unless --allow-remote.
func TestRefusesRemoteListen(t *testing.T) {
	var errb bytes.Buffer
	if code := run([]string{"--listen", "0.0.0.0:0"}, io.Discard, &errb, nil); code != 2 || !strings.Contains(errb.String(), "--allow-remote") {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if checkListen("0.0.0.0:0", true) != nil || checkListen("[::1]:0", false) != nil || checkListen("localhost:1", false) != nil {
		t.Fatal("allowed addresses refused")
	}
}
