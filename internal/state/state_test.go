package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestResolveRootUsesDesktopDefaultAndExpandsCustomHome(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	got, err := ResolveRoot("", home)
	if err != nil || got != filepath.Join(home, "Desktop", "RevKit") {
		t.Fatalf("ResolveRoot default = %q, %v", got, err)
	}
	got, err = ResolveRoot("~/Tools/RevKit", home)
	if err != nil || got != filepath.Join(home, "Tools", "RevKit") {
		t.Fatalf("ResolveRoot custom = %q, %v", got, err)
	}
}

func TestResolveRootRejectsEmptyHomeAndNUL(t *testing.T) {
	if _, err := ResolveRoot("", ""); err == nil {
		t.Fatal("ResolveRoot accepted an empty home")
	}
	if _, err := ResolveRoot(filepath.Join(t.TempDir(), "bad\x00path"), t.TempDir()); err == nil {
		t.Fatal("ResolveRoot accepted a NUL byte")
	}
	if _, err := ResolveRoot("~another/RevKit", t.TempDir()); err == nil {
		t.Fatal("ResolveRoot accepted an unsupported named-user path")
	}
}

func TestResolveRootResolvesRelativePathFromWorkingDirectory(t *testing.T) {
	want, err := filepath.Abs(filepath.Join("relative", "RevKit"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ResolveRoot(filepath.Join("relative", "RevKit"), t.TempDir())
	if err != nil || got != want {
		t.Fatalf("ResolveRoot relative = %q, %v; want %q", got, err, want)
	}
}

func TestVersionComparison(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"1.9.0", "1.10.0", -1},
		{"v2.0.0", "2.0.0", 0},
		{"2026.09.15", "2026.10.01", -1},
		{"2.0", "1.99.99", 1},
		{"v2.1.0-rc.1", "2.1.0", -1},
		{"2.0.0+build.2", "2.0.0+build.1", 0},
	} {
		if got := CompareVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestDecisionDoesNotReinstallCurrentTool(t *testing.T) {
	if got := Decide(true, false, "2.5.0", "2.5.0"); got != ActionNone {
		t.Fatalf("current tool action = %q, want none", got)
	}
	if got := Decide(false, false, "", "2.5.0"); got != ActionInstall {
		t.Fatalf("missing tool action = %q, want install", got)
	}
	if got := Decide(true, false, "2.4.0", "2.5.0"); got != ActionUpdate {
		t.Fatalf("outdated tool action = %q, want update", got)
	}
	if got := Decide(true, true, "2.5.0", "2.5.0"); got != ActionRepair {
		t.Fatalf("broken tool action = %q, want repair", got)
	}
}

func TestNeedsCheckUsesSevenDayInterval(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	if !NeedsCheck(now, time.Time{}) {
		t.Fatal("NeedsCheck should check a tool with no recorded check")
	}
	if NeedsCheck(now, now.Add(-time.Hour)) {
		t.Fatal("NeedsCheck should skip a recently checked tool")
	}
	if !NeedsCheck(now, now.Add(-CheckInterval)) {
		t.Fatal("NeedsCheck should recheck a week-old tool")
	}
}

func TestStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	in := State{Root: filepath.Join(t.TempDir(), "Desktop", "RevKit"), Version: "v0.1.0", Tools: map[string]ToolState{"capa": {Version: "10.0.0", Digest: "sha256:abc"}}}
	if err := Save(path, in); err != nil {
		t.Fatal(err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if out.Root != in.Root || out.Tools["capa"].Version != "10.0.0" {
		t.Fatalf("Load() = %#v, want %#v", out, in)
	}
}

func TestSaveLeavesUnchangedStateFileAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	value := State{Root: filepath.Join(t.TempDir(), "RevKit"), Version: "v0.1.0", Tools: map[string]ToolState{}}
	if err := Save(path, value); err != nil {
		t.Fatal(err)
	}
	old := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, value); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.ModTime().Equal(old) {
		t.Fatalf("unchanged state file was rewritten at %s", info.ModTime())
	}
}
