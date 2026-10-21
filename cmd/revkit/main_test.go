package main

import (
	"bytes"
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
	for _, command := range []string{"install", "update", "doctor", "list", "triage", "dashboard", "uninstall"} {
		if !strings.Contains(stdout.String(), "revkit "+command) {
			t.Errorf("help output does not list %q", command)
		}
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
	missingSample := filepath.Join(root, "workspace", "samples", "rust", "hello", "main.rs")
	if _, err := os.Stat(missingSample); err != nil {
		t.Fatalf("embedded sample was not copied: %v", err)
	}
	for _, dir := range []string{"bin", "tools/gui", "tools/cli", "workspace/reports", "workspace/notes", "dashboard"} {
		if info, err := os.Stat(filepath.Join(root, dir)); err != nil || !info.IsDir() {
			t.Errorf("installation directory %q missing or invalid: %v", dir, err)
		}
	}
}

func TestUninstallRemovesOnlyRecordedToolsAndPreservesWorkspace(t *testing.T) {
	root, home := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	for _, path := range []string{
		filepath.Join(root, "tools", "cli", "capa", "capa"),
		filepath.Join(root, "tools", "cli", "floss", "floss"),
		filepath.Join(root, "dashboard", "index.html"),
		filepath.Join(root, "bin", "revkit"),
		filepath.Join(root, "workspace", "notes", "keep.md"),
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
	link := filepath.Join(home, ".local", "bin", "revkit")
	if err := os.MkdirAll(filepath.Dir(link), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "bin", "revkit"), link); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(home, ".profile")
	profileText := "before\n# >>> RevKit PATH >>>\nRevKit path lines\n# <<< RevKit PATH <<<\nafter\n"
	if err := os.WriteFile(profile, []byte(profileText), 0644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	catalog := catalog.Catalog{Tools: []catalog.Tool{
		{ID: "capa", Type: "standalone", Interface: "CLI"},
		{ID: "floss", Type: "standalone", Interface: "CLI"},
	}}
	if code := uninstall(root, catalog, false, &stdout, &stderr); code != 0 {
		t.Fatalf("uninstall exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(root, "tools", "cli", "capa")); !os.IsNotExist(err) {
		t.Errorf("recorded tool was not removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "tools", "cli", "floss", "floss")); err != nil {
		t.Errorf("unrecorded tool path was removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "workspace", "notes", "keep.md")); err != nil {
		t.Errorf("workspace note was removed: %v", err)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Errorf("managed PATH symlink was not removed: %v", err)
	}
	if contents, err := os.ReadFile(profile); err != nil || string(contents) != "before\nafter\n" {
		t.Errorf("profile outside the RevKit block changed: %q, %v", contents, err)
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
	if err := state.Save(filepath.Join(root, "state.json"), state.State{Root: root, Tools: map[string]state.ToolState{"capa": {Path: "tools/cli/capa/capa"}}}); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	catalog := catalog.Catalog{Tools: []catalog.Tool{{ID: "capa", Type: "standalone", Interface: "CLI"}}}
	if code := uninstall(root, catalog, false, &stdout, &stderr); code == 0 {
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
	if _, err := os.Stat(filepath.Join(target, "bin")); !os.IsNotExist(err) {
		t.Fatalf("ensureRoot modified the symlink target: %v", err)
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
	if _, err := os.Stat(filepath.Join(root, "bin")); !os.IsNotExist(err) {
		t.Fatalf("install created directories before refusing foreign state: %v", err)
	}
}

func TestResolveInstalledRootUsesStateAndFallsBackForOtherExecutables(t *testing.T) {
	home, root := t.TempDir(), t.TempDir()
	executable := filepath.Join(root, "bin", "revkit")
	if err := os.MkdirAll(filepath.Dir(executable), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, []byte("cli"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := state.Save(filepath.Join(root, "state.json"), state.State{Root: root, Tools: map[string]state.ToolState{}}); err != nil {
		t.Fatal(err)
	}
	got, err := resolveInstalledRoot(executable, home)
	if err != nil || got != root {
		t.Fatalf("resolveInstalledRoot() = %q, %v; want %q", got, err, root)
	}
	got, err = resolveInstalledRoot(filepath.Join(t.TempDir(), "revkit"), home)
	want := filepath.Join(home, "Desktop", "RevKit")
	if err != nil || got != want {
		t.Fatalf("resolveInstalledRoot() fallback = %q, %v; want %q", got, err, want)
	}
}

func TestRunRejectsUnknownCommandWithUsageExit(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"not-a-command"}, &stdout, &stderr); code != 2 {
		t.Fatalf("unknown command exit = %d, want 2; output=%s", code, stderr.String())
	}
}
