package dashboard

import (
	"strings"
	"testing"

	"github.com/Voldigoade/revkit/internal/catalog"
)

func TestRenderIncludesWorkflowLanguageAndEscapedToolData(t *testing.T) {
	c := catalog.Catalog{SchemaVersion: 1, Tools: []catalog.Tool{{
		ID: "sample", Name: "sample <tool>", CategoryFR: "Statique", CategoryEN: "Static", Type: "system", Architectures: []string{"amd64"},
		DescriptionEN: "Inspect <binary>", DescriptionFR: "Inspecter <binaire>", WhenEN: "Use it", WhenFR: "Utilisez-le", AvoidEN: "Avoid it", AvoidFR: "À éviter", Usage: "sample FILE", DocsURL: "https://example.org/docs",
	}}}
	html, err := Render(c, map[string]ToolStatus{"sample": {Status: "missing", Version: "—", Path: ""}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"FR", "EN", "Identify", "Inspect structure", "Find clues", "Static analysis", "Dynamic analysis", "Verify hypothesis", "data-fr=\"Statique\" data-en=\"Static\"", "&lt;tool&gt;", "Inspect &lt;binary&gt;", "sample FILE", "https://example.org/docs"} {
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
	c := catalog.Catalog{SchemaVersion: 1, Tools: []catalog.Tool{}}
	first, err := Render(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Render(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("Render output changed without catalog or status changes")
	}
}
