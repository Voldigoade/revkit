package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Voldigoade/revkit/internal/catalog"
	"github.com/Voldigoade/revkit/internal/state"
)

func TestRunHelpListsSupportedCommands(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run --help exit = %d, stderr=%s", code, stderr.String())
	}
	for _, command := range []string{"install", "update", "doctor", "list", "analyze", "dashboard", "version", "uninstall"} {
		if !strings.Contains(stdout.String(), "revkit "+command) {
			t.Errorf("help output does not list %q", command)
		}
	}
	if strings.Contains(stdout.String(), "triage") || strings.Contains(stdout.String(), string(rune(0x2014))) {
		t.Fatal("help includes a removed command or forbidden em dash")
	}
}

func TestEnsureRootPreservesWorkspaceDataAndCopiesSamplesOnce(t *testing.T) {
	root := t.TempDir()
	userSample := filepath.Join(root, "workspace", "samples", "c", "hello", "hello.c")
	if err := os.MkdirAll(filepath.Dir(userSample), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userSample, []byte("user-owned sample\n"), 0644); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := ensureRoot(root); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(userSample)
	if err != nil || string(data) != "user-owned sample\n" {
		t.Fatalf("existing sample changed: data=%q err=%v", data, err)
	}
	if _, err := os.Stat(filepath.Join(root, "workspace", "samples", "rust", "hello", "main.rs")); err != nil {
		t.Fatalf("embedded sample was not copied: %v", err)
	}
	for _, dir := range []string{"tools/gui", "tools/cli", "workspace/reports", "workspace/notes", "dashboard"} {
		if info, err := os.Stat(filepath.Join(root, dir)); err != nil || !info.IsDir() {
			t.Errorf("installation directory %q missing or invalid: %v", dir, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "bin")); !os.IsNotExist(err) {
		t.Fatalf("CLI binary was copied into the data root: %v", err)
	}
}

func TestUninstallRemovesRecordedToolsAndPreservesWorkspace(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{
		filepath.Join(root, "tools", "cli", "capa", "capa"),
		filepath.Join(root, "tools", "cli", "floss", "floss"),
		filepath.Join(root, "dashboard", "index.html"),
		filepath.Join(root, "workspace", "notes", "keep.md"),
		filepath.Join(root, "workspace", "reports", "keep.md"),
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("user data\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := state.Save(filepath.Join(root, "state.json"), state.State{
		Root: root, Tools: map[string]state.ToolState{"capa": {Path: "tools/cli/capa/capa"}},
	}); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	catalogue := catalog.Catalog{Tools: []catalog.Tool{
		{ID: "capa", Type: "standalone", Interface: "CLI"},
		{ID: "floss", Type: "standalone", Interface: "CLI"},
	}}
	if code := uninstall(root, catalogue, false, &stdout, &stderr); code != 0 {
		t.Fatalf("uninstall exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(root, "tools", "cli", "capa")); !os.IsNotExist(err) {
		t.Errorf("recorded tool was not removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "tools", "cli", "floss", "floss")); err != nil {
		t.Errorf("unrecorded tool path was removed: %v", err)
	}
	for _, path := range []string{"workspace/notes/keep.md", "workspace/reports/keep.md"} {
		if _, err := os.Stat(filepath.Join(root, path)); err != nil {
			t.Errorf("workspace data was removed: %s: %v", path, err)
		}
	}
}

func TestUninstallRefusesUnmanagedRoot(t *testing.T) {
	root := t.TempDir()
	tool := filepath.Join(root, "tools", "cli", "capa", "keep")
	if err := os.MkdirAll(filepath.Dir(tool), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tool, []byte("keep"), 0644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := uninstall(root, catalog.Catalog{}, false, &stdout, &stderr); code == 0 {
		t.Fatal("uninstall accepted a root without matching RevKit state")
	}
	if _, err := os.Stat(tool); err != nil {
		t.Fatalf("unmanaged file was removed: %v", err)
	}
}

func TestUninstallRefusesSymlinkedToolParent(t *testing.T) {
	root, external := t.TempDir(), t.TempDir()
	tool := filepath.Join(external, "cli", "capa", "keep")
	if err := os.MkdirAll(filepath.Dir(tool), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tool, []byte("keep"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(root, "tools")); err != nil {
		t.Fatal(err)
	}
	if err := state.Save(filepath.Join(root, "state.json"), state.State{Root: root, Tools: map[string]state.ToolState{"capa": {Path: "tools/cli/capa/keep"}}}); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	catalogue := catalog.Catalog{Tools: []catalog.Tool{{ID: "capa", Type: "standalone", Interface: "CLI"}}}
	if code := uninstall(root, catalogue, false, &stdout, &stderr); code == 0 {
		t.Fatal("uninstall accepted a symlinked tool parent")
	}
	if _, err := os.Stat(tool); err != nil {
		t.Fatalf("symlink target was removed: %v", err)
	}
}

func TestEnsureRootRejectsSymlinkedRoot(t *testing.T) {
	target, rootLink := t.TempDir(), filepath.Join(t.TempDir(), "RevKit")
	if err := os.Symlink(target, rootLink); err != nil {
		t.Fatal(err)
	}
	if err := ensureRoot(rootLink); err == nil {
		t.Fatal("ensureRoot accepted a symlinked installation root")
	}
	if _, err := os.Stat(filepath.Join(target, "tools")); !os.IsNotExist(err) {
		t.Fatalf("ensureRoot modified the symlink target: %v", err)
	}
}

func TestDashboardAndTUIRejectSymlinkedRoot(t *testing.T) {
	target, root := t.TempDir(), filepath.Join(t.TempDir(), "RevKit")
	if err := os.Symlink(target, root); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := runDashboard(root, catalog.Catalog{}, false, &stdout, &stderr); code == 0 {
		t.Fatal("dashboard accepted a symlinked installation root")
	}
	if code := runTUI(root, catalog.Catalog{}); code == 0 {
		t.Fatal("TUI accepted a symlinked installation root")
	}
	if _, err := os.Stat(filepath.Join(target, "workspace")); !os.IsNotExist(err) {
		t.Fatalf("commands modified the symlink target: %v", err)
	}
}

func TestEnsureRootDoesNotCopySamplesThroughSymlinkedParent(t *testing.T) {
	root, external := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "workspace", "samples"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(root, "workspace", "samples", "c")); err != nil {
		t.Fatal(err)
	}
	if err := ensureRoot(root); err == nil {
		t.Fatal("ensureRoot copied samples through a symlink")
	}
	entries, err := os.ReadDir(external)
	if err != nil || len(entries) != 0 {
		t.Fatalf("symlink target was modified: entries=%v err=%v", entries, err)
	}
}

func TestInstallRefusesStateFromAnotherRoot(t *testing.T) {
	root := t.TempDir()
	if err := state.Save(filepath.Join(root, "state.json"), state.State{Root: filepath.Join(root, "other"), Tools: map[string]state.ToolState{}}); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := install(root, catalog.Catalog{}, false, true, &stdout, &stderr); code == 0 {
		t.Fatal("install accepted state belonging to another root")
	}
	if _, err := os.Stat(filepath.Join(root, "tools")); !os.IsNotExist(err) {
		t.Fatalf("install created directories before refusing foreign state: %v", err)
	}
}

func TestResolveRootUsesSavedCustomPath(t *testing.T) {
	home := t.TempDir()
	config := state.ConfigPath(home, filepath.Join(home, "config"))
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
	root := filepath.Join(home, "Tools", "Reverse Lab", "RevKit")
	if err := state.SaveSelectedRoot(config, root); err != nil {
		t.Fatal(err)
	}
	got, err := resolveRoot("")
	if err != nil || got != root {
		t.Fatalf("resolveRoot() = %q, %v; want %q", got, err, root)
	}
}

func TestAnalyzeJSONWritesSharedReportArtifactsAndDoesNotExecuteTarget(t *testing.T) {
	root := filepath.Join(t.TempDir(), "RevKit With Spaces")
	marker := filepath.Join(t.TempDir(), "executed")
	target := filepath.Join(t.TempDir(), "target.sh")
	if err := os.WriteFile(target, []byte("#!/bin/sh\nprintf ran > '"+marker+"'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--root", root, "analyze", target, "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("analyze exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	var value struct {
		SchemaVersion  int    `json:"schema_version"`
		TargetExecuted bool   `json:"target_executed"`
		Summary        string `json:"summary"`
		Metadata       struct {
			ID string `json:"id"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &value); err != nil {
		t.Fatalf("analyze JSON is invalid: %v\n%s", err, stdout.String())
	}
	if value.SchemaVersion != 1 || value.TargetExecuted || value.Metadata.ID == "" || value.Summary == "" {
		t.Fatalf("analyze JSON is missing report fields: %#v", value)
	}
	for _, ext := range []string{".md", ".json", ".html"} {
		if _, err := os.Stat(filepath.Join(root, "workspace", "reports", value.Metadata.ID+ext)); err != nil {
			t.Errorf("report artifact %s missing: %v", ext, err)
		}
	}
	dashboard, err := os.ReadFile(filepath.Join(root, "dashboard", "index.html"))
	if err != nil || !strings.Contains(string(dashboard), "../workspace/reports/"+value.Metadata.ID+".html") {
		t.Fatalf("dashboard report index was not refreshed: err=%v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("analyzed target was executed: %v", err)
	}
}

func TestRunVersionDoesNotNeedInstallationRoot(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"version"}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "RevKit ") {
		t.Fatalf("version command exit=%d output=%q err=%q", code, stdout.String(), stderr.String())
	}
}

func TestRunRejectsUnknownCommandWithUsageExit(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"not-a-command"}, &stdout, &stderr); code != 2 {
		t.Fatalf("unknown command exit = %d, want 2; output=%s", code, stderr.String())
	}
}
