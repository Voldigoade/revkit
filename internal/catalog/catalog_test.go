package catalog

import (
	"strings"
	"testing"
)

func TestLoadEmbeddedManifest(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Tools) < 25 {
		t.Fatalf("expected curated system and standalone tools, got %d", len(c.Tools))
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejectsDuplicateIDsAndMissingTranslations(t *testing.T) {
	c := Catalog{SchemaVersion: 1, Tools: []Tool{
		{ID: "same", Name: "One", Type: "system", Interface: "CLI", CategoryFR: "CLI", CategoryEN: "CLI", Package: "one", InstallMethod: "apt", OfficialSource: "https://packages.debian.org/stable/one", DocsURL: "https://example.org/docs", Architectures: []string{"amd64"}, DescriptionEN: "description", DescriptionFR: "description", WhenEN: "when", WhenFR: "when", AvoidEN: "avoid", AvoidFR: "avoid", Usage: "one"},
		{ID: "same", Name: "Two", Type: "system", Interface: "CLI", CategoryFR: "CLI", CategoryEN: "CLI", Package: "two", InstallMethod: "apt", OfficialSource: "https://packages.debian.org/stable/two", DocsURL: "https://example.org/docs", Architectures: []string{"amd64"}, DescriptionEN: "description", DescriptionFR: "description", WhenEN: "when", WhenFR: "when", AvoidEN: "avoid", AvoidFR: "avoid", Usage: "two"},
	}}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("Validate() error = %v, want duplicate ID error", err)
	}
}

func TestValidateRejectsUnsafePathsAndUnsupportedArchitectures(t *testing.T) {
	base := Tool{
		ID: "sample", Name: "Sample", CategoryFR: "Outil", CategoryEN: "Tool", Type: "system", Interface: "CLI",
		Package: "sample", InstallMethod: "apt", OfficialSource: "https://packages.debian.org/stable/sample", DocsURL: "https://example.org/docs",
		Architectures: []string{"amd64"}, DescriptionEN: "description", DescriptionFR: "description", WhenEN: "when", WhenFR: "when",
		AvoidEN: "avoid", AvoidFR: "avoid", Usage: "sample FILE",
	}
	for _, tc := range []struct {
		name string
		edit func(*Tool)
	}{
		{"path traversal id", func(t *Tool) { t.ID = "../escape" }},
		{"unsupported architecture", func(t *Tool) { t.Architectures = []string{"arm64"} }},
		{"missing English category", func(t *Tool) { t.CategoryEN = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tool := base
			tc.edit(&tool)
			if err := (Catalog{SchemaVersion: 1, Tools: []Tool{tool}}).Validate(); err == nil {
				t.Fatal("Validate() accepted invalid catalog data")
			}
		})
	}
}

func TestSelectAssetRequiresExactArchitecture(t *testing.T) {
	tool := Tool{ID: "capa", Type: "standalone", Architectures: []string{"amd64"}, AssetPattern: "capa-*-linux.zip", AssetExclude: []string{"arm64", "py313"}, OfficialSource: "https://github.com/mandiant/capa/releases"}
	assets := []Asset{
		{Name: "capa-v1-linux-arm64.zip", URL: "https://github.com/mandiant/capa/releases/download/v1/capa-v1-linux-arm64.zip", Digest: "sha256:" + strings.Repeat("a", 64)},
		{Name: "capa-v1-linux-py313.zip", URL: "https://github.com/mandiant/capa/releases/download/v1/capa-v1-linux-py313.zip", Digest: "sha256:" + strings.Repeat("b", 64)},
		{Name: "capa-v1-linux.zip", URL: "https://github.com/mandiant/capa/releases/download/v1/capa-v1-linux.zip", Digest: "sha256:" + strings.Repeat("c", 64)},
	}
	got, err := SelectAsset(tool, assets, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "capa-v1-linux.zip" {
		t.Fatalf("selected %q, want x86-64 asset", got.Name)
	}
	if _, err := SelectAsset(tool, assets[:2], "amd64"); err == nil {
		t.Fatal("SelectAsset accepted a release containing only incompatible assets")
	}
}

func TestSelectAssetRejectsUntrustedURLAndMissingDigest(t *testing.T) {
	tool := Tool{ID: "floss", Type: "standalone", Architectures: []string{"amd64"}, AssetPattern: "floss-*-linux.zip", OfficialSource: "https://github.com/mandiant/flare-floss/releases"}
	for _, asset := range []Asset{
		{Name: "floss-v1-linux.zip", URL: "https://mirror.example/floss.zip", Digest: "sha256:" + strings.Repeat("a", 64)},
		{Name: "floss-v1-linux.zip", URL: "https://github.com/mandiant/flare-floss/releases/download/v1/floss.zip"},
		{Name: "floss-v1-linux.zip", URL: "https://github.com/other/flare-floss/releases/download/v1/floss-v1-linux.zip", Digest: "sha256:" + strings.Repeat("a", 64)},
	} {
		if _, err := SelectAsset(tool, []Asset{asset}, "amd64"); err == nil {
			t.Fatalf("SelectAsset accepted unsafe asset %#v", asset)
		}
	}
}

func TestGitHubReleaseRepoAcceptsOnlyOfficialRepositoryReleasePaths(t *testing.T) {
	repo, err := GitHubReleaseRepo("https://github.com/mandiant/capa/releases")
	if err != nil || repo != "mandiant/capa" {
		t.Fatalf("GitHubReleaseRepo() = %q, %v", repo, err)
	}
	for _, source := range []string{
		"https://github.com.evil.example/mandiant/capa/releases",
		"https://github.com/mandiant/capa/releases/../../evil",
		"https://user@github.com/mandiant/capa/releases",
		"https://github.com/mandiant/capa/releases?download=1",
		"https://github.com/mandiant/releases",
	} {
		if _, err := GitHubReleaseRepo(source); err == nil {
			t.Errorf("GitHubReleaseRepo accepted %q", source)
		}
	}
}
