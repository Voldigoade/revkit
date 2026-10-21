package doctor

import (
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/Voldigoade/revkit/internal/catalog"
	"github.com/Voldigoade/revkit/internal/state"
)

type Check struct {
	Tool          catalog.Tool
	Status        string
	Version       string
	Path          string
	ExpectedArch  string
	InstalledArch string
	Detail        string
	Suggested     string
}

type Checker struct {
	Root             string
	State            state.State
	LookPath         func(string) (string, error)
	Output           func(string, ...string) ([]byte, error)
	PackageInstalled func(string) (bool, error)
}

func New(root string, st state.State) Checker {
	return Checker{
		Root: root, State: st,
		LookPath: exec.LookPath,
		Output: func(name string, args ...string) ([]byte, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, name, args...)
			return cmd.CombinedOutput()
		},
		PackageInstalled: func(pkg string) (bool, error) {
			cmd := exec.Command("dpkg-query", "-W", "-f=${db:Status-Status}", "--", pkg)
			out, err := cmd.Output()
			if err != nil {
				var exitErr *exec.ExitError
				if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
					return false, nil
				}
				return false, err
			}
			return strings.TrimSpace(string(out)) == "installed", nil
		},
	}
}

func (c Checker) All(tools []catalog.Tool) []Check {
	checks := make([]Check, 0, len(tools))
	for _, tool := range tools {
		checks = append(checks, c.Tool(tool))
	}
	return checks
}

func (c Checker) Tool(tool catalog.Tool) Check {
	check := Check{Tool: tool, Status: "missing", ExpectedArch: "x86_64", Version: "—"}
	if !hasArch(tool.Architectures, runtime.GOARCH) {
		check.Status = "broken"
		check.Detail = "tool manifest does not support this host architecture"
		check.Suggested = "use a supported x86-64 release"
		return check
	}
	if tool.Type == "system" {
		return c.checkSystem(check)
	}
	return c.checkStandalone(check)
}

func (c Checker) checkSystem(check Check) Check {
	tool := check.Tool
	if c.PackageInstalled != nil {
		installed, err := c.PackageInstalled(tool.Package)
		if err != nil {
			check.Status = "broken"
			check.Detail = fmt.Sprintf("cannot inspect APT package %s: %v", tool.Package, err)
			check.Suggested = "check dpkg-query and run revkit doctor again"
			return check
		}
		if !installed {
			check.Detail = fmt.Sprintf("APT package %s is not installed", tool.Package)
			check.Suggested = "run revkit install"
			return check
		}
	}
	path, lookupErr := c.LookPath(tool.DetectCommand)
	if tool.ModuleCheck != "" {
		path, lookupErr = c.LookPath("python3")
		if lookupErr == nil {
			_, lookupErr = c.Output(path, "-c", "import "+tool.ModuleCheck)
		}
	}
	if lookupErr != nil {
		check.Status = "broken"
		check.Detail = "APT package is installed but the command or module is unavailable"
		check.Suggested = "run revkit install to repair the package"
		return check
	}
	check.Path = path
	if err := checkExecutable(path); err != nil {
		check.Status = "broken"
		check.Detail = err.Error()
		check.Suggested = "reinstall the package from the Debian or Ubuntu repository"
		return check
	}
	arch, isELF, err := executableArch(path)
	if err != nil {
		check.Status, check.Detail = "broken", err.Error()
		check.Suggested = "reinstall the package from the Debian or Ubuntu repository"
		return check
	}
	if isELF && arch != check.ExpectedArch {
		check.Status, check.InstalledArch = "broken", arch
		check.Detail = fmt.Sprintf("expected architecture: %s; installed architecture: %s", check.ExpectedArch, arch)
		check.Suggested = "run revkit install to reinstall the x86-64 package"
		return check
	}
	check.Status = "installed"
	if len(tool.VersionArgs) > 0 && c.Output != nil {
		if out, err := c.Output(path, tool.VersionArgs...); err == nil {
			check.Version = firstLine(string(out))
		}
	}
	return check
}

func (c Checker) checkStandalone(check Check) Check {
	tool := check.Tool
	entry, recorded := c.State.Tools[tool.ID]
	dir := "cli"
	if tool.Interface != "CLI" {
		dir = "gui"
	}
	base := filepath.Join(c.Root, "tools", dir, tool.ID)
	path := entry.Path
	if path != "" && !filepath.IsAbs(path) {
		path = filepath.Join(c.Root, path)
	}
	if path == "" {
		path = findExecutable(base, tool.Executable)
	}
	if path == "" {
		check.Detail = "standalone tool is not installed"
		check.Suggested = "run revkit install"
		return check
	}
	check.Path = path
	if !pathWithin(base, path) {
		check.Status = "broken"
		check.Detail = "recorded launcher is outside RevKit's managed tool directory"
		check.Suggested = "run revkit install to restore the managed release"
		return check
	}
	if err := checkExecutable(path); err != nil {
		check.Status, check.Detail = "broken", err.Error()
		check.Suggested = "run revkit install to repair the release"
		return check
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || !pathWithin(base, resolved) {
		check.Status = "broken"
		check.Detail = "launcher resolves outside RevKit's managed tool directory"
		check.Suggested = "run revkit install to restore the managed release"
		return check
	}
	arch, isELF, err := executableArch(path)
	if err != nil {
		check.Status, check.Detail = "broken", err.Error()
		check.Suggested = "run revkit install to repair the release"
		return check
	}
	if isELF && arch != check.ExpectedArch {
		check.Status, check.InstalledArch = "broken", arch
		check.Detail = fmt.Sprintf("expected architecture: %s; installed architecture: %s", check.ExpectedArch, arch)
		check.Suggested = "run revkit install to install the correct upstream asset"
		return check
	}
	if tool.JavaMajor > 0 {
		java, err := c.LookPath("java")
		if err != nil {
			check.Status, check.Detail = "broken", "Java runtime is missing"
			check.Suggested = "install the OpenJDK version listed by RevKit"
			return check
		}
		out, err := c.Output(java, "-version")
		major := javaMajor(string(out))
		if err != nil || major < tool.JavaMajor {
			check.Status = "broken"
			check.Detail = fmt.Sprintf("Ghidra requires Java %d or newer; detected Java %d", tool.JavaMajor, major)
			check.Suggested = "install the OpenJDK version listed by RevKit"
			return check
		}
	}
	check.Status = "installed"
	if recorded && entry.Version != "" {
		check.Version = entry.Version
	} else if len(tool.VersionArgs) > 0 && c.Output != nil {
		if out, err := c.Output(path, tool.VersionArgs...); err == nil {
			check.Version = firstLine(string(out))
		}
	}
	return check
}

func pathWithin(directory, path string) bool {
	directory, err := filepath.Abs(directory)
	if err != nil {
		return false
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(directory, path)
	if err != nil || relative == "." || relative == ".." {
		return false
	}
	return !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func checkExecutable(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("launcher is missing: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		if _, err := filepath.EvalSymlinks(path); err != nil {
			return fmt.Errorf("launcher is a broken symlink")
		}
	}
	info, err = os.Stat(path)
	if err != nil {
		return fmt.Errorf("launcher cannot be read: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return fmt.Errorf("launcher is not an executable file")
	}
	return nil
}

func executableArch(path string) (string, bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", false, err
	}
	magic := make([]byte, 4)
	n, readErr := io.ReadFull(file, magic)
	closeErr := file.Close()
	if closeErr != nil {
		return "", false, closeErr
	}
	if n != len(magic) || string(magic) != "\x7fELF" {
		return "", false, nil
	}
	if readErr != nil {
		return "", true, readErr
	}
	f, err := elf.Open(path)
	if err != nil {
		return "", true, err
	}
	defer f.Close()
	if f.Machine == elf.EM_X86_64 {
		return "x86_64", true, nil
	}
	return strings.ToLower(f.Machine.String()), true, nil
}

func findExecutable(root, name string) string {
	var found string
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || found != "" {
			return nil
		}
		if entry.IsDir() || entry.Name() != name {
			return nil
		}
		info, err := entry.Info()
		if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
			found = path
		}
		return nil
	})
	return found
}

func javaMajor(output string) int {
	re := regexp.MustCompile(`(?:version\s+")?([0-9]+)(?:\.([0-9]+))?`)
	match := re.FindStringSubmatch(output)
	if len(match) < 2 {
		return 0
	}
	major := 0
	_, _ = fmt.Sscanf(match[1], "%d", &major)
	if major == 1 && len(match) > 2 {
		_, _ = fmt.Sscanf(match[2], "%d", &major)
	}
	return major
}

func firstLine(text string) string {
	line := strings.TrimSpace(strings.SplitN(text, "\n", 2)[0])
	if line == "" {
		return "—"
	}
	return line
}

func hasArch(items []string, arch string) bool {
	for _, item := range items {
		if item == arch {
			return true
		}
	}
	return false
}
