package dashboard

import (
	"strings"
	"testing"
	"time"

	"github.com/Voldigoade/revkit/internal/catalog"
	"github.com/Voldigoade/revkit/internal/report"
)

func TestRenderIncludesWorkflowLanguageAndEscapedToolData(t *testing.T) {
	c := catalog.Catalog{SchemaVersion: 2, Tools: []catalog.Tool{{
		ID: "sample", Name: "sample <tool>", Severity: "optional", CategoryFR: "Statique", CategoryEN: "Static", Type: "system", Architectures: []string{"amd64"},
		DescriptionEN: "Inspect <binary>", DescriptionFR: "Inspecter <binaire>", WhenEN: "Use it", WhenFR: "Utilisez-le", AvoidEN: "Avoid it", AvoidFR: "À éviter", Usage: "sample FILE", DocsURL: "https://example.org/docs",
	}}}
	html, err := Render(c, map[string]ToolStatus{"sample": {Status: "missing", Version: "n/a", Path: ""}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"<title>RevKit</title>", "<div class=\"brand\">RevKit</div>", "FR | EN", "Identify", "Inspect structure", "Find clues", "Static analysis", "Dynamic analysis", "Verify hypothesis", "data-fr=\"Statique\" data-en=\"Static\"", "&lt;tool&gt;", "Inspect &lt;binary&gt;", "sample FILE", "https://example.org/docs", "Tools", "Reports"} {
		if !strings.Contains(html, want) {
			t.Errorf("dashboard HTML does not contain %q", want)
		}
	}
	if strings.Contains(html, "sample <tool>") {
		t.Fatal("tool data was not escaped")
	}
	for _, want := range []string{"[objet] + [action voulue] + [contexte]", "[object] + [wanted action] + [context]", "Documentation officielle", "Official documentation", "data-fr=\"absent\"", "data-en=\"missing\""} {
		if !strings.Contains(html, want) {
			t.Errorf("dashboard HTML does not contain %q", want)
		}
	}
}

func TestRenderIsDeterministic(t *testing.T) {
	c := catalog.Catalog{SchemaVersion: 2, Tools: []catalog.Tool{}}
	first, err := Render(c, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Render(c, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("Render output changed without catalog or status changes")
	}
}

func TestRenderReportIndexUsesStaticRelativeLinks(t *testing.T) {
	created := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	html, err := Render(catalog.Catalog{SchemaVersion: 2}, nil, []report.IndexEntry{{
		ID: "20261022-120000-abcd", Filename: "sample.exe", Format: "PE", Architecture: "x86-64", Size: 4096, CreatedAt: created, Summary: "PE32+ Windows console executable.",
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"sample.exe", "PE", "x86-64", "4,096", "2026-10-22", "PE32", "Windows console executable.", "../workspace/reports/20261022-120000-abcd.html"} {
		if !strings.Contains(html, want) {
			t.Errorf("report index does not contain %q", want)
		}
	}
	if strings.Contains(html, "fetch(") || strings.Contains(html, "RevKit - ") {
		t.Fatal("dashboard depends on local fetch or decorates its title/brand")
	}
}
