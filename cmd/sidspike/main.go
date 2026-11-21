// Command sidspike is the PACKET-SPIKE experiment (Story 1.4): one Smart-ID RP
// API v3 anonymous device-link authentication against the public demo
// environment, verified end to end, with only redacted output.
//
// The human step (scanning the QR in the Smart-ID demo app) can be replaced by
// the demo environment's automated testing interface (-mock-document), which
// simulates the device for SK's published test accounts.
//
// Usage:
//
//	go run ./cmd/sidspike -mock-document PNOEE-40404040009-MOCK-Q -fixtures internal/smartid/testdata/live
//	go run ./cmd/sidspike            # prints a QR link for a human with the demo app
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/tomkabel/eidbridge/internal/logx"
	"github.com/tomkabel/eidbridge/internal/smartid"
)

func main() {
	base := flag.String("base", "https://sid.demo.sk.ee/smart-id-rp", "RP API base URL (demo only)")
	mockBase := flag.String("mock-base", "https://sid.demo.sk.ee/mock", "demo automated testing interface")
	doc := flag.String("mock-document", "", "demo test document number; empty means wait for a human scan")
	fixtures := flag.String("fixtures", "", "directory to write captured demo request/response fixtures")
	caDir := flag.String("ca-dir", "trust/demo/smartid-auth-ca", "directory with demo authentication CA certificates (PEM)")
	timeout := flag.Duration("timeout", 3*time.Minute, "overall deadline")
	flag.Parse()
	log := logx.New(os.Stderr, slog.LevelDebug)

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	os.Exit(run(ctx, log, *base, *mockBase, *doc, *fixtures, *caDir))
}

func run(ctx context.Context, log *slog.Logger, base, mockBase, doc, fixtures, caDir string) int {
	trust, err := smartid.LoadCADir(caDir)
	if err != nil {
		log.Error("load demo CA", "err", err)
		return 2
	}
	rec := &smartid.Recorder{}
	c, err := smartid.NewClient(smartid.Config{
		BaseURL: base, RPUUID: smartid.DemoRPUUID, RPName: smartid.DemoRPName,
		SchemeName: smartid.SchemeDemo, Trust: trust, MinCertLevel: smartid.LevelQualified,
		Status:   smartid.NoStatusCheck{Reason: "spike: revocation not checked"},
		Recorder: rec,
	})
	if err != nil {
		log.Error("client", "err", err)
		return 2
	}
	s, err := c.StartDeviceLink(ctx, smartid.DeviceLinkRequest{Flow: smartid.FlowQR, DisplayText60: "eidbridge spike"})
	if err != nil {
		log.Error("start", "err", err)
		return 1
	}
	link, err := s.QRLink(time.Now())
	if err != nil {
		log.Error("link", "err", err)
		return 1
	}
	if doc != "" {
		if err := smartid.MockSubmitDeviceLink(ctx, mockBase, doc, link, rec); err != nil {
			log.Error("mock device-link", "err", err)
			return 1
		}
		log.Info("device link submitted to demo automated testing interface")
	} else {
		fmt.Println("Scan with the Smart-ID demo app within 60 s (the link changes every second; this one is a snapshot):")
		fmt.Println(link)
	}
	var st *smartid.Status
	for {
		st, err = c.Poll(ctx, s.ID, 10*time.Second)
		if err != nil {
			log.Error("poll", "err", err)
			return 1
		}
		if st.State == "COMPLETE" {
			break
		}
	}
	id, err := c.Verify(s, st, nil)
	if fixtures != "" {
		if werr := writeFixtures(fixtures, s, rec); werr != nil {
			log.Error("fixtures", "err", werr)
		}
	}
	if err != nil {
		log.Error("verification failed", "reason", smartid.ReasonOf(err), "err", err)
		fmt.Println("NOT AUTHENTICATED:", smartid.ReasonOf(err))
		return 1
	}
	log.Info("verified", "country", id.Country, "level", id.CertLevel, "flow", id.FlowType)
	fmt.Printf("AUTHENTICATED country=%s certificateLevel=%s flowType=%s subject=[personal] chain=verified signature=verified\n", id.Country, id.CertLevel, id.FlowType)
	return 0
}

func writeFixtures(dir string, s *smartid.Session, rec *smartid.Recorder) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for i, x := range rec.Exchanges {
		b, _ := json.MarshalIndent(x, "", "  ")
		name := fmt.Sprintf("%02d-%s.json", i, x.Name)
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			return err
		}
	}
	meta := map[string]any{
		"captured":           time.Now().UTC().Format(time.RFC3339),
		"source":             "sid.demo.sk.ee public demo with SK automated testing interface; demo test account only",
		"rpChallenge":        s.RPChallengeB64(),
		"interactions":       s.Interactions,
		"relyingPartyName":   smartid.DemoRPName,
		"schemeName":         smartid.SchemeDemo,
		"initialCallbackUrl": s.InitialCallbackURL,
		"interactionsSHA256": fmt.Sprintf("%x", sha256.Sum256([]byte(s.Interactions))),
	}
	b, _ := json.MarshalIndent(meta, "", "  ")
	return os.WriteFile(filepath.Join(dir, "session-meta.json"), b, 0o644)
}
