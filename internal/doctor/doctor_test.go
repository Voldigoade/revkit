package doctor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Voldigoade/revkit/internal/catalog"
	"github.com/Voldigoade/revkit/internal/state"
)

func TestSystemCheckReportsInstalledPathAndVersion(t *testing.T) {
	command := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(command, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	checker := Checker{
		LookPath:         func(name string) (string, error) { return command, nil },
		Output:           func(name string, args ...string) ([]byte, error) { return []byte("file-5.45\n"), nil },
		PackageInstalled: func(string) (bool, error) { return true, nil },
	}
	tool := catalog.Tool{ID: "file", Name: "file", Type: "system", Package: "file", DetectCommand: "file", Architectures: []string{"amd64"}, VersionArgs: []string{"--version"}}
	got := checker.Tool(tool)
	if got.Status != "installed" || got.Path != command || got.Version != "file-5.45" {
		t.Fatalf("Tool() = %#v", got)
	}
}

func TestUnavailableOptionalPackageIsWarningAndDoesNotSuggestInstallLoop(t *testing.T) {
	tool := catalog.Tool{ID: "radare2", Name: "radare2", Severity: "optional", Type: "system", Package: "radare2", DetectCommand: "r2", Architectures: []string{"amd64"}}
	checker := Checker{
		Root:             t.TempDir(),
		LookPath:         func(string) (string, error) { return "", os.ErrNotExist },
		PackageInstalled: func(string) (bool, error) { return false, nil },
		PackageCandidate: func(string) (string, error) { return "(none)", nil },
	}
	got := checker.Tool(tool)
	if got.Status != "unavailable" || IsFatal(got) || !strings.Contains(got.Detail, "configured repositories") {
		t.Fatalf("optional package check = %#v", got)
	}
	if strings.Contains(strings.ToLower(got.Suggested), "revkit install") {
		t.Fatalf("unavailable package suggests an install loop: %q", got.Suggested)
	}
}

func TestDoctorFailsOnlyForCoreToolProblems(t *testing.T) {
	if !IsFatal(Check{Tool: catalog.Tool{Severity: "core"}, Status: "missing"}) {
		t.Fatal("missing core tool was not fatal")
	}
	for _, status := range []string{"missing", "unavailable", "broken"} {
		if IsFatal(Check{Tool: catalog.Tool{Severity: "optional"}, Status: status}) {
			t.Errorf("optional %s tool was fatal", status)
		}
	}
}

func TestSystemCheckRequiresTheCatalogPackage(t *testing.T) {
	command := filepath.Join(t.TempDir(), "gcc")
	if err := os.WriteFile(command, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	checker := Checker{
		LookPath:         func(string) (string, error) { return command, nil },
		PackageInstalled: func(string) (bool, error) { return false, nil },
	}
	tool := catalog.Tool{ID: "gcc-multilib", Name: "GCC multilib", Type: "system", Package: "gcc-multilib", DetectCommand: "gcc", Architectures: []string{"amd64"}}
	got := checker.Tool(tool)
	if got.Status != "missing" || !strings.Contains(got.Detail, "gcc-multilib") {
		t.Fatalf("system check ignored the specific package: %#v", got)
	}
}

func TestPythonModuleCheckReportsModuleVersion(t *testing.T) {
	python := filepath.Join(t.TempDir(), "python3")
	if err := os.WriteFile(python, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	checker := Checker{
		LookPath: func(string) (string, error) { return python, nil },
		Output: func(_ string, args ...string) ([]byte, error) {
			if len(args) == 2 && args[0] == "-c" && args[1] == "import elftools" {
				return nil, nil
			}
			return []byte("0.32\n"), nil
		},
		PackageInstalled: func(string) (bool, error) { return true, nil },
	}
	tool := catalog.Tool{
		ID: "python3-pyelftools", Name: "pyelftools", Type: "system", Package: "python3-pyelftools", DetectCommand: "python3",
		ModuleCheck: "elftools", VersionArgs: []string{"-c", "import importlib.metadata; print(importlib.metadata.version('pyelftools'))"},
		Architectures: []string{"amd64"},
	}
	got := checker.Tool(tool)
	if got.Status != "installed" || got.Version != "0.32" {
		t.Fatalf("Python module check = %#v", got)
	}
}

func TestSystemCheckDistinguishesMissingAndBrokenSymlink(t *testing.T) {
	broken := filepath.Join(t.TempDir(), "missing-link")
	if err := os.Symlink(filepath.Join(t.TempDir(), "absent"), broken); err != nil {
		t.Fatal(err)
	}
	tool := catalog.Tool{ID: "file", Name: "file", Type: "system", Package: "file", DetectCommand: "file", Architectures: []string{"amd64"}}
	checker := Checker{
		LookPath:         func(string) (string, error) { return broken, nil },
		PackageInstalled: func(string) (bool, error) { return true, nil },
	}
	got := checker.Tool(tool)
	if got.Status != "broken" || !strings.Contains(got.Detail, "broken symlink") {
		t.Fatalf("broken symlink check = %#v", got)
	}
	checker.LookPath = func(string) (string, error) { return "", fmt.Errorf("not found") }
	checker.PackageInstalled = func(string) (bool, error) { return false, nil }
	got = checker.Tool(tool)
	if got.Status != "missing" {
		t.Fatalf("missing tool check = %#v", got)
	}
}

func TestGhidraCheckRequiresCompatibleJava(t *testing.T) {
	root := t.TempDir()
	launcher := filepath.Join(root, "tools", "gui", "ghidra", "ghidraRun")
	if err := os.MkdirAll(filepath.Dir(launcher), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(launcher, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	checker := Checker{
		Root: root, State: state.State{Tools: map[string]state.ToolState{"ghidra": {Path: launcher, Version: "12.1.4"}}},
		LookPath:         func(name string) (string, error) { return "/usr/bin/" + name, nil },
		Output:           func(name string, args ...string) ([]byte, error) { return []byte("openjdk version \"17.0.1\"\n"), nil },
		PackageInstalled: func(string) (bool, error) { return true, nil },
	}
	tool := catalog.Tool{ID: "ghidra", Name: "Ghidra", Type: "standalone", Architectures: []string{"amd64"}, Executable: "ghidraRun", JavaMajor: 21}
	got := checker.Tool(tool)
	if got.Status != "broken" || !strings.Contains(got.Detail, "requires Java 21") {
		t.Fatalf("Ghidra compatibility check = %#v", got)
	}
	checker.Output = func(name string, args ...string) ([]byte, error) { return []byte("openjdk version \"21.0.1\"\n"), nil }
	got = checker.Tool(tool)
	if got.Status != "installed" || got.Version != "12.1.4" {
		t.Fatalf("compatible Ghidra check = %#v", got)
	}
}

func TestStandaloneDoctorRejectsPathOutsideManagedToolDirectory(t *testing.T) {
	root := t.TempDir()
	external := filepath.Join(t.TempDir(), "capa")
	if err := os.WriteFile(external, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	called := false
	checker := Checker{
		Root: root, State: state.State{Tools: map[string]state.ToolState{"capa": {Path: external}}},
		LookPath: func(string) (string, error) { return "", fmt.Errorf("not found") },
		Output:   func(string, ...string) ([]byte, error) { called = true; return []byte("version"), nil },
	}
	tool := catalog.Tool{ID: "capa", Name: "capa", Type: "standalone", Interface: "CLI", Architectures: []string{"amd64"}, Executable: "capa", VersionArgs: []string{"--version"}}
	got := checker.Tool(tool)
	if got.Status != "broken" || called {
		t.Fatalf("doctor accepted or executed an external launcher: check=%#v outputCalled=%v", got, called)
	}
}

func TestExecutableArchitectureReadsELFMachine(t *testing.T) {
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	arch, isELF, err := executableArch(path)
	if err != nil || !isELF || arch != "x86_64" {
		t.Fatalf("executableArch(%s) = %q, %v, %v", path, arch, isELF, err)
	}
}

func TestExecutableArchitectureRejectsMalformedELF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken")
	if err := os.WriteFile(path, []byte("\x7fELF\x01\x01"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := executableArch(path); err == nil {
		t.Fatal("executableArch accepted a malformed ELF file")
	}
}

func TestJavaMajor(t *testing.T) {
	for input, want := range map[string]int{"openjdk version \"21.0.2\"": 21, "openjdk version \"1.8.0_402\"": 8, "unknown": 0} {
		if got := javaMajor(input); got != want {
			t.Errorf("javaMajor(%q) = %d, want %d", input, got, want)
		}
	}
}
