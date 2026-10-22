package catalog

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

//go:embed manifest.json
var files embed.FS

type Catalog struct {
	SchemaVersion int    `json:"schema_version"`
	Tools         []Tool `json:"tools"`
}

type Tool struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Severity        string   `json:"severity"`
	CategoryFR      string   `json:"category_fr"`
	CategoryEN      string   `json:"category_en"`
	Type            string   `json:"type"`
	Interface       string   `json:"interface"`
	Package         string   `json:"package,omitempty"`
	RequiresPackage []string `json:"requires_packages,omitempty"`
	DetectCommand   string   `json:"detect_command,omitempty"`
	VersionArgs     []string `json:"version_args,omitempty"`
	ModuleCheck     string   `json:"module_check,omitempty"`
	Architectures   []string `json:"architectures"`
	OfficialSource  string   `json:"official_source"`
	InstallMethod   string   `json:"install_method"`
	AssetPattern    string   `json:"asset_pattern,omitempty"`
	AssetExclude    []string `json:"asset_exclude,omitempty"`
	AssetFormat     string   `json:"asset_format,omitempty"`
	Executable      string   `json:"executable,omitempty"`
	DescriptionFR   string   `json:"description_fr"`
	DescriptionEN   string   `json:"description_en"`
	WhenFR          string   `json:"when_to_use_fr"`
	WhenEN          string   `json:"when_to_use_en"`
	AvoidFR         string   `json:"when_not_to_use_fr"`
	AvoidEN         string   `json:"when_not_to_use_en"`
	Usage           string   `json:"basic_usage"`
	DocsURL         string   `json:"documentation_url"`
	JavaMajor       int      `json:"java_major,omitempty"`
}

type Asset struct {
	Name   string `json:"name"`
	URL    string `json:"browser_download_url"`
	Digest string `json:"digest"`
}

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-fA-F]{64}$`)
var idPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
var packagePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*$`)

func Load() (Catalog, error) {
	data, err := files.ReadFile("manifest.json")
	if err != nil {
		return Catalog{}, err
	}
	var c Catalog
	if err := json.Unmarshal(data, &c); err != nil {
		return Catalog{}, fmt.Errorf("decode tool manifest: %w", err)
	}
	if err := c.Validate(); err != nil {
		return Catalog{}, fmt.Errorf("validate tool manifest: %w", err)
	}
	return c, nil
}

func (c Catalog) Validate() error {
	if c.SchemaVersion != 2 {
		return fmt.Errorf("unsupported schema version %d", c.SchemaVersion)
	}
	if len(c.Tools) == 0 {
		return fmt.Errorf("manifest has no tools")
	}
	seen := make(map[string]bool, len(c.Tools))
	for _, t := range c.Tools {
		if t.ID == "" || t.Name == "" || t.CategoryFR == "" || t.CategoryEN == "" {
			return fmt.Errorf("tool has an empty id, name, or translated category")
		}
		if !idPattern.MatchString(t.ID) {
			return fmt.Errorf("tool %q has an unsafe id", t.ID)
		}
		if seen[t.ID] {
			return fmt.Errorf("duplicate tool id %q", t.ID)
		}
		seen[t.ID] = true
		if t.Type != "system" && t.Type != "standalone" {
			return fmt.Errorf("tool %q has invalid type %q", t.ID, t.Type)
		}
		if t.Severity != "core" && t.Severity != "optional" {
			return fmt.Errorf("tool %q has invalid severity %q", t.ID, t.Severity)
		}
		if t.Interface != "CLI" && t.Interface != "GUI" && t.Interface != "GUI/CLI" {
			return fmt.Errorf("tool %q has invalid interface %q", t.ID, t.Interface)
		}
		if len(t.Architectures) == 0 {
			return fmt.Errorf("tool %q has no supported architectures", t.ID)
		}
		for _, arch := range t.Architectures {
			if arch != "amd64" {
				return fmt.Errorf("tool %q declares unsupported architecture %q", t.ID, arch)
			}
		}
		if t.OfficialSource == "" || t.InstallMethod == "" {
			return fmt.Errorf("tool %q is missing source or install method", t.ID)
		}
		source, err := url.Parse(t.OfficialSource)
		if err != nil || source.Scheme != "https" || source.Host == "" || source.User != nil || source.Port() != "" || source.RawQuery != "" || source.Fragment != "" {
			return fmt.Errorf("tool %q has invalid official source URL", t.ID)
		}
		if t.DescriptionEN == "" || t.DescriptionFR == "" || t.WhenEN == "" || t.WhenFR == "" || t.AvoidEN == "" || t.AvoidFR == "" || t.Usage == "" || t.DocsURL == "" {
			return fmt.Errorf("tool %q is missing educational content", t.ID)
		}
		if t.Type == "system" && t.Package == "" {
			return fmt.Errorf("system tool %q has no APT package", t.ID)
		}
		if t.Type == "system" && (!packagePattern.MatchString(t.Package) || t.InstallMethod != "apt") {
			return fmt.Errorf("system tool %q has invalid APT package metadata", t.ID)
		}
		if t.Type == "standalone" && (t.AssetPattern == "" || t.AssetFormat == "" || t.Executable == "") {
			return fmt.Errorf("standalone tool %q is missing release metadata", t.ID)
		}
		if t.Type == "standalone" {
			if t.InstallMethod != "github-release" || filepath.Base(t.Executable) != t.Executable || strings.ContainsAny(t.Executable, `/\\`) || t.Executable == "." || t.Executable == ".." || strings.ContainsAny(t.AssetPattern, `/\\`) {
				return fmt.Errorf("standalone tool %q has unsafe release metadata", t.ID)
			}
			if t.AssetFormat != "zip" && t.AssetFormat != "tar.xz" && t.AssetFormat != "appimage" {
				return fmt.Errorf("standalone tool %q has unsupported archive format %q", t.ID, t.AssetFormat)
			}
			for _, pkg := range t.RequiresPackage {
				if !packagePattern.MatchString(pkg) {
					return fmt.Errorf("standalone tool %q has invalid required package %q", t.ID, pkg)
				}
			}
			if _, err := GitHubReleaseRepo(t.OfficialSource); err != nil {
				return fmt.Errorf("tool %q has invalid official release source: %w", t.ID, err)
			}
		}
		if t.DocsURL != "" {
			u, err := url.Parse(t.DocsURL)
			if err != nil || u.Scheme != "https" || u.Host == "" {
				return fmt.Errorf("tool %q has invalid documentation URL", t.ID)
			}
		}
	}
	return nil
}

func GitHubReleaseRepo(source string) (string, error) {
	u, err := url.Parse(source)
	if err != nil || u.Scheme != "https" || u.Host != "github.com" || u.User != nil || u.Port() != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("source must be an official GitHub HTTPS releases URL")
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] != "releases" || parts[0] == "." || parts[0] == ".." || parts[1] == "." || parts[1] == ".." {
		return "", fmt.Errorf("source must identify one GitHub repository's releases")
	}
	return url.PathEscape(parts[0]) + "/" + url.PathEscape(parts[1]), nil
}

func (c Catalog) Find(id string) (Tool, bool) {
	for _, t := range c.Tools {
		if t.ID == id {
			return t, true
		}
	}
	return Tool{}, false
}

func (c Catalog) Packages() []string {
	set := map[string]bool{}
	for _, t := range c.Tools {
		if t.Type == "system" {
			set[t.Package] = true
		}
		for _, p := range t.RequiresPackage {
			set[p] = true
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func SelectAsset(tool Tool, assets []Asset, arch string) (Asset, error) {
	if tool.Type != "standalone" {
		return Asset{}, fmt.Errorf("tool %q is not standalone", tool.ID)
	}
	if !contains(tool.Architectures, arch) {
		return Asset{}, fmt.Errorf("tool %q does not support architecture %q", tool.ID, arch)
	}
	repo, err := GitHubReleaseRepo(tool.OfficialSource)
	if err != nil {
		return Asset{}, fmt.Errorf("tool %q: %w", tool.ID, err)
	}
	var matches []Asset
	for _, asset := range assets {
		if strings.Contains(asset.Name, "/") || strings.Contains(asset.Name, "\\") || path.Base(asset.Name) != asset.Name {
			continue
		}
		ok, err := filepath.Match(tool.AssetPattern, asset.Name)
		if err != nil {
			return Asset{}, fmt.Errorf("tool %q has invalid asset pattern: %w", tool.ID, err)
		}
		if !ok {
			continue
		}
		excluded := false
		for _, part := range tool.AssetExclude {
			if strings.Contains(strings.ToLower(asset.Name), strings.ToLower(part)) {
				excluded = true
				break
			}
		}
		if excluded || !validReleaseAsset(asset, repo) {
			continue
		}
		matches = append(matches, asset)
	}
	if len(matches) != 1 {
		return Asset{}, fmt.Errorf("tool %q: expected one verified %s release asset, found %d", tool.ID, arch, len(matches))
	}
	return matches[0], nil
}

func validReleaseAsset(a Asset, repo string) bool {
	u, err := url.Parse(a.URL)
	if err != nil || u.Scheme != "https" || u.Host != "github.com" || u.User != nil || u.Port() != "" || u.RawQuery != "" || u.Fragment != "" || !digestPattern.MatchString(a.Digest) {
		return false
	}
	prefix := "/" + repo + "/releases/download/"
	return strings.HasPrefix(u.Path, prefix) && path.Base(u.Path) == a.Name
}

func contains(items []string, item string) bool {
	for _, value := range items {
		if value == item {
			return true
		}
	}
	return false
}
