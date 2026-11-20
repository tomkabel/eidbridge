package docscheck

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/tomkabel/eidbridge/internal/oidc"
)

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", p))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func section(doc, heading string) string {
	i := strings.Index(doc, "## "+heading)
	if i < 0 {
		return ""
	}
	rest := doc[i+3:]
	if j := strings.Index(rest, "\n## "); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// Story 3.1 AC: every claim emitted by internal/oidc appears in the table.
func TestDataFlowClaimsMatchCode(t *testing.T) {
	sec := section(read(t, "docs/data-flow.md"), "Claims emitted")
	got := map[string]bool{}
	for _, line := range strings.Split(sec, "\n") {
		if !strings.HasPrefix(line, "| `") {
			continue
		}
		cell := strings.Split(line, "|")[1]
		for _, m := range regexp.MustCompile("`([a-z_]+)`").FindAllStringSubmatch(cell, -1) {
			got[m[1]] = true
		}
	}
	want := oidc.ClaimNames()
	var missing, extra []string
	for _, c := range want {
		if !got[c] {
			missing = append(missing, c)
		}
		delete(got, c)
	}
	for c := range got {
		extra = append(extra, c)
	}
	sort.Strings(extra)
	if len(missing) > 0 || len(extra) > 0 {
		t.Fatalf("docs/data-flow.md claims table: missing %v, not emitted by code %v", missing, extra)
	}
}

// A15: the sequence diagram has the browser-to-bridge front channel, the
// app-to-scheme leg and trust-boundary groupings.
func TestDataFlowDocDiagramEdges(t *testing.T) {
	doc := read(t, "docs/data-flow.md")
	m := regexp.MustCompile("(?s)~~~mermaid\n(.*?)~~~").FindStringSubmatch(doc)
	if m == nil {
		t.Fatal("no mermaid block")
	}
	d := m[1]
	for _, want := range []string{"sequenceDiagram", "box Device of the user", "box Operator host", "box Scheme operator", "box Integrator",
		"B->>E: front channel", "A->>S:", "S->>A:", "C->>E: back channel"} {
		if !strings.Contains(d, want) {
			t.Errorf("diagram lacks %q", want)
		}
	}
}

func TestRequiredDocsLinked(t *testing.T) {
	readme := read(t, "README.md")
	for _, l := range []string{"docs/legal.md", "CONTRIBUTING.md", "docs/data-flow.md", "docs/security.md", "SECURITY.md", "docs/configuration.md", "docs/api-tracking.md", "CHANGELOG.md", "docs/idp/keycloak.md"} {
		if !strings.Contains(readme, "]("+l+")") {
			t.Errorf("README does not link %s", l)
		}
	}
	if !strings.Contains(read(t, "docs/security.md"), "](data-flow.md)") {
		t.Error("docs/security.md does not link data-flow.md")
	}
	if !strings.Contains(read(t, "README.md"), "Not affiliated with, endorsed by or certified by") {
		t.Error("README lacks the unofficial notice")
	}
}

// Story 2.7 (E16): the Keycloak document shows how to reject acr=demo.
func TestKeycloakDocStubRejectsDemoACR(t *testing.T) {
	doc := read(t, "docs/idp/keycloak.md")
	if !strings.Contains(doc, "acr=demo") || !strings.Contains(doc, "/demo") || !strings.Contains(strings.ToLower(doc), "reject") {
		t.Fatal("keycloak doc must explain rejecting acr=demo")
	}
}
