package oidc

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// Subjects computes ADR-007 subject identifiers:
//
//	sub = base64url(HMAC-SHA256(K_sub[v], "eidbridge-sub-v1" 0x00 sector 0x00 type 0x00 country 0x00 code))
//
// A raw or plainly hashed personal code is never a sub.
type Subjects struct {
	Keys      map[int][]byte // K_sub versions, 32 bytes each
	Current   int
	Migration *Migration // optional K_sub rotation window
}

// Migration declares a subject change: a K_sub rotation (From → To) and/or
// a client's sector change. During the window, each declared client receives
// previous_sub computed with K_sub[From] and the client's old sector.
type Migration struct {
	From, To int
	Started  time.Time
	Days     int               // 1–90
	Clients  map[string]string // client ID → old sector ("g:public" or "c:<id>")
}

// Active reports whether the window is open at now.
func (m *Migration) Active(now time.Time) bool {
	return m != nil && now.Before(m.Started.Add(time.Duration(m.Days)*24*time.Hour))
}

// Validate checks key sizes and the migration declaration.
func (s *Subjects) Validate() error {
	if len(s.Keys[s.Current]) != 32 {
		return errors.New("oidc: K_sub for the current version must be 32 bytes")
	}
	if s.Migration != nil {
		m := s.Migration
		if m.Days < 1 || m.Days > 90 {
			return errors.New("oidc: migration_window_days must be 1 to 90")
		}
		if m.To != s.Current || len(s.Keys[m.From]) != 32 {
			return errors.New("oidc: migration must go from a configured old K_sub version to the current one")
		}
	}
	return nil
}

var serialRe = regexp.MustCompile(`^(PNO|PAS|IDC)$`)
var countryRe = regexp.MustCompile(`^[A-Z]{2}$`)

// Sub computes the subject for a sector ("g:public" or "c:<sector_id>").
func (s *Subjects) Sub(version int, sector, idType, country, code string) (string, error) {
	k := s.Keys[version]
	if len(k) != 32 {
		return "", errors.New("oidc: unknown K_sub version")
	}
	if !serialRe.MatchString(idType) || !countryRe.MatchString(country) || code == "" {
		return "", errors.New("oidc: identity fields not usable for sub")
	}
	m := hmac.New(sha256.New, k)
	for i, part := range []string{"eidbridge-sub-v1", sector, idType, country, code} {
		if i > 0 {
			m.Write([]byte{0})
		}
		m.Write([]byte(part))
	}
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil)), nil
}

// subjectLock records each client's subject settings so a silent change is
// refused at startup (E14). It holds configuration only, no user data.
type subjectLock struct {
	Clients map[string]subjectSettings `json:"clients"`
}

type subjectSettings struct {
	Mode    string `json:"sub_mode"`
	Sector  string `json:"sector"`
	Version int    `json:"k_sub_version"`
}

// CheckSubjectLock compares the configured subject settings with dir's
// subject-config.json. A change in mode, sector or K_sub version for a client
// fails unless a migration declares that client. The file is then updated.
func CheckSubjectLock(dir string, clients []Client, subs *Subjects) error {
	path := filepath.Join(dir, "subject-config.json")
	cur := subjectLock{Clients: map[string]subjectSettings{}}
	for _, c := range clients {
		cur.Clients[c.ID] = subjectSettings{Mode: c.SubMode, Sector: c.sector(), Version: subs.Current}
	}
	b, err := os.ReadFile(path)
	if err == nil {
		var old subjectLock
		if err := json.Unmarshal(b, &old); err != nil {
			return fmt.Errorf("oidc: subject-config.json: %w", err)
		}
		for id, o := range old.Clients {
			n, ok := cur.Clients[id]
			if !ok || n == o {
				continue
			}
			bad := fmt.Errorf("oidc: client %s changed sub_mode, sector_id or K_sub version without a declared migration", id)
			if subs.Migration == nil {
				return bad
			}
			oldSector, declared := subs.Migration.Clients[id]
			if !declared || (o.Version != n.Version && o.Version != subs.Migration.From) || oldSector != o.Sector {
				return bad
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	nb, _ := json.MarshalIndent(cur, "", "  ")
	return os.WriteFile(path, nb, 0o600)
}
