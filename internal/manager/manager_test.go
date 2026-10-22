package manager

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Voldigoade/revkit/internal/catalog"
	"github.com/Voldigoade/revkit/internal/state"
)

func TestPackageActionIsIdempotent(t *testing.T) {
	for _, tc := range []struct {
		installed bool
		broken    bool
		current   string
		candidate string
		want      string
	}{
		{false, false, "", "1.0", "install"},
		{true, false, "1.0", "1.0", "none"},
		{true, false, "1.0", "1.1", "update"},
		{true, true, "1.0", "1.0", "repair"},
	} {
		if got := PackageAction(tc.installed, tc.broken, tc.current, tc.candidate); got != tc.want {
			t.Errorf("PackageAction(%v, %v, %q, %q) = %q, want %q", tc.installed, tc.broken, tc.current, tc.candidate, got, tc.want)
		}
	}
}

type packageRunner struct {
	command       string
	installed     bool
	updates       int
	installations int
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func (r *packageRunner) Run(_ context.Context, name string, args ...string) error {
	if name == "sudo" {
		if len(args) == 0 || args[0] != "apt-get" {
			return fmt.Errorf("unexpected sudo command: %v", args)
		}
		name = "apt-get"
		args = args[1:]
	}
	if name != "apt-get" || len(args) == 0 {
		return fmt.Errorf("unexpected command: %s %v", name, args)
	}
	switch args[0] {
	case "update":
		r.updates++
	case "install":
		r.installations++
		r.installed = true
		if err := os.WriteFile(r.command, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unexpected apt-get arguments: %v", args)
	}
	return nil
}

func (r *packageRunner) Output(_ context.Context, name string, args ...string) ([]byte, error) {
	switch name {
	case "dpkg-query":
		if r.installed {
			return []byte("installed\t1.0\n"), nil
		}
		return nil, exec.Command("false").Run()
	case "apt-cache":
		return []byte("Candidate: 1.0\n"), nil
	default:
		return nil, fmt.Errorf("unexpected query: %s %v", name, args)
	}
}

type unavailablePackageRunner struct{}

func (unavailablePackageRunner) Run(context.Context, string, ...string) error {
	return fmt.Errorf("unexpected APT action")
}

type failingOptionalPackageRunner struct{}

func (failingOptionalPackageRunner) Run(_ context.Context, name string, args ...string) error {
	if name == "sudo" && len(args) > 0 && args[0] == "apt-get" {
		args = args[1:]
		name = "apt-get"
	}
	if name == "apt-get" && len(args) > 0 && args[0] == "update" {
		return nil
	}
	return fmt.Errorf("simulated APT failure")
}

func (failingOptionalPackageRunner) Output(_ context.Context, name string, _ ...string) ([]byte, error) {
	if name == "dpkg-query" {
		return []byte("not-installed\t"), nil
	}
	if name == "apt-cache" {
		return []byte("Candidate: 1.0\n"), nil
	}
	return nil, fmt.Errorf("unexpected command %s", name)
}

func TestOptionalPackageInstallFailureIsWarning(t *testing.T) {
	var output strings.Builder
	manager := Manager{
		Root: t.TempDir(), Catalog: catalog.Catalog{Tools: []catalog.Tool{{
			ID: "optional", Name: "Optional", Severity: "optional", Type: "system", Package: "optional", DetectCommand: "optional", Architectures: []string{"amd64"},
		}}},
		State: &state.State{Tools: map[string]state.ToolState{}}, Runner: failingOptionalPackageRunner{}, Out: &output,
	}
	if err := manager.Sync(context.Background(), false); err != nil {
		t.Fatalf("optional APT failure was fatal: %v", err)
	}
	if !strings.Contains(output.String(), "Optional APT packages optional could not be installed") {
		t.Fatalf("optional package warning was not shown: %s", output.String())
	}
}

func (unavailablePackageRunner) Output(_ context.Context, name string, _ ...string) ([]byte, error) {
	switch name {
	case "dpkg-query":
		return []byte("unknown\t\n"), nil
	case "apt-cache":
		return []byte("Candidate: (none)\n"), nil
	default:
		return nil, fmt.Errorf("unexpected query %s", name)
	}
}

func TestSyncInstallsMissingPackageOnce(t *testing.T) {
	root := t.TempDir()
	command := filepath.Join(root, "helper")
	runner := &packageRunner{command: command}
	tool := catalog.Tool{
		ID: "helper", Name: "Helper", Type: "system", Package: "helper", DetectCommand: command,
		Architectures: []string{"amd64"},
	}
	manager := Manager{
		Root: root, Catalog: catalog.Catalog{Tools: []catalog.Tool{tool}}, State: &state.State{Tools: map[string]state.ToolState{}},
		Runner: runner, Out: &strings.Builder{}, Now: func() time.Time { return time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC) },
	}
	for i := 0; i < 2; i++ {
		if err := manager.Sync(context.Background(), false); err != nil {
			t.Fatalf("Sync() pass %d: %v", i+1, err)
		}
	}
	if runner.installations != 1 || runner.updates != 1 {
		t.Fatalf("APT actions repeated: installs=%d updates=%d", runner.installations, runner.updates)
	}
}

func TestValidateArchivePath(t *testing.T) {
	for _, unsafe := range []string{"../outside", "a/../../outside", "/etc/passwd", "a\\..\\outside"} {
		if _, err := archivePath(unsafe); err == nil {
			t.Errorf("archivePath accepted %q", unsafe)
		}
	}
	got, err := archivePath("ghidra/support/launch.sh")
	if err != nil || got != filepath.Join("ghidra", "support", "launch.sh") {
		t.Fatalf("archivePath returned %q, %v", got, err)
	}
}

func TestDownloadClientRejectsUntrustedRedirect(t *testing.T) {
	client := downloadClient(&http.Client{})
	target, err := url.Parse("https://example.org/payload")
	if err != nil {
		t.Fatal(err)
	}
	if err := client.CheckRedirect(&http.Request{URL: target}, []*http.Request{{}}); err == nil {
		t.Fatal("download client accepted a redirect to an untrusted host")
	}
}

func TestSyncDoesNotDowngradeNewerStandaloneTool(t *testing.T) {
	root := t.TempDir()
	launcher := filepath.Join(root, "tools", "cli", "sample", "sample")
	if err := os.MkdirAll(filepath.Dir(launcher), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(launcher, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	tool := catalog.Tool{
		ID: "sample", Name: "Sample", Type: "standalone", Interface: "CLI", Architectures: []string{"amd64"},
		OfficialSource: "https://github.com/example/sample/releases", AssetPattern: "sample-*-linux.zip", AssetFormat: "zip", Executable: "sample",
	}
	current := state.ToolState{Version: "2.0.0", Digest: "sha256:current", Path: "tools/cli/sample/sample"}
	manager := Manager{
		Root: root, Catalog: catalog.Catalog{Tools: []catalog.Tool{tool}},
		State: &state.State{Root: root, Tools: map[string]state.ToolState{"sample": current}, APTUpdated: now},
		HTTPClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.URL.Path != "/repos/example/sample/releases/latest" {
				return nil, fmt.Errorf("unexpected request path %q", request.URL.Path)
			}
			return &http.Response{
				StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header),
				Body: io.NopCloser(strings.NewReader(`{"tag_name":"v1.9.0","assets":[]}`)), Request: request,
			}, nil
		})}, APIBase: "https://api.github.com", Out: &strings.Builder{}, Now: func() time.Time { return now },
	}
	if err := manager.Sync(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	got := manager.State.Tools["sample"]
	if got.Version != current.Version || got.Digest != current.Digest {
		t.Fatalf("newer installed version was replaced: %#v", got)
	}
}

func TestSyncSkipsToolsWithUnavailableAPTDependencies(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	tool := catalog.Tool{
		ID: "ghidra", Name: "Ghidra", Type: "standalone", Interface: "GUI/CLI", Architectures: []string{"amd64"},
		OfficialSource: "https://github.com/NationalSecurityAgency/ghidra/releases", AssetPattern: "ghidra_*.zip", AssetFormat: "zip", Executable: "ghidraRun",
		RequiresPackage: []string{"openjdk-21-jre"},
	}
	var output strings.Builder
	manager := Manager{
		Root: root, Catalog: catalog.Catalog{Tools: []catalog.Tool{tool}},
		State:  &state.State{Root: root, Tools: map[string]state.ToolState{}, APTUpdated: now},
		Runner: unavailablePackageRunner{}, Out: &output, Now: func() time.Time { return now },
		HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("should not contact GitHub when a required APT package is unavailable")
		})},
	}
	if err := manager.Sync(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "openjdk-21-jre") || !strings.Contains(output.String(), "skipping release management") {
		t.Fatalf("missing dependency was not reported: %s", output.String())
	}
}

func TestExtractZipRejectsTraversalAndExtractsFiles(t *testing.T) {
	root := t.TempDir()
	archivePath := filepath.Join(root, "sample.zip")
	file, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(file)
	entry, err := zw.Create("bundle/bin/tool")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte("tool data")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(root, "out")
	if err := extractZip(archivePath, dest); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dest, "bundle", "bin", "tool"))
	if err != nil || string(data) != "tool data" {
		t.Fatalf("extracted data = %q, %v", data, err)
	}

	badPath := filepath.Join(root, "bad.zip")
	badFile, err := os.Create(badPath)
	if err != nil {
		t.Fatal(err)
	}
	badWriter := zip.NewWriter(badFile)
	badEntry, err := badWriter.Create("../../escaped")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = badEntry.Write([]byte("unsafe"))
	_ = badWriter.Close()
	_ = badFile.Close()
	if err := extractZip(badPath, filepath.Join(root, "bad-out")); err == nil {
		t.Fatal("extractZip accepted a path traversal entry")
	}
}
