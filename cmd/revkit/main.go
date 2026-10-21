package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	revkit "github.com/Voldigoade/revkit"
	"github.com/Voldigoade/revkit/internal/catalog"
	"github.com/Voldigoade/revkit/internal/dashboard"
	"github.com/Voldigoade/revkit/internal/doctor"
	"github.com/Voldigoade/revkit/internal/host"
	"github.com/Voldigoade/revkit/internal/manager"
	"github.com/Voldigoade/revkit/internal/state"
	"github.com/Voldigoade/revkit/internal/triage"
)

var version = "v0.1.0"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		printUsage(stdout)
		return 0
	}
	rootOverride := ""
	if args[0] == "--root" {
		if len(args) < 3 || args[1] == "" {
			fmt.Fprintln(stderr, "--root requires a path before the command")
			return 2
		}
		rootOverride = args[1]
		args = args[2:]
	} else if strings.HasPrefix(args[0], "--root=") {
		rootOverride = strings.TrimPrefix(args[0], "--root=")
		args = args[1:]
		if rootOverride == "" || len(args) == 0 {
			fmt.Fprintln(stderr, "--root requires a path before the command")
			return 2
		}
	}
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}
	command, rest := args[0], args[1:]
	root, err := resolveRoot(rootOverride)
	if err != nil {
		fmt.Fprintf(stderr, "revkit: %v\n", err)
		return 2
	}
	c, err := catalog.Load()
	if err != nil {
		fmt.Fprintf(stderr, "revkit: %v\n", err)
		return 1
	}
	switch command {
	case "install":
		dryRun, ok := parseDryRun("install", rest, stderr)
		if !ok {
			return 2
		}
		return install(root, c, false, dryRun, stdout, stderr)
	case "update":
		dryRun, ok := parseDryRun("update", rest, stderr)
		if !ok {
			return 2
		}
		return install(root, c, true, dryRun, stdout, stderr)
	case "doctor":
		if len(rest) != 0 {
			fmt.Fprintln(stderr, "usage: revkit doctor")
			return 2
		}
		return runDoctor(root, c, stdout, stderr)
	case "list":
		if len(rest) != 0 {
			fmt.Fprintln(stderr, "usage: revkit list")
			return 2
		}
		return runList(root, c, stdout, stderr)
	case "triage":
		if len(rest) != 1 {
			fmt.Fprintln(stderr, "usage: revkit triage FILE")
			return 2
		}
		return runTriage(root, rest[0], stdout, stderr)
	case "dashboard":
		dryRun, ok := parseDryRun("dashboard", rest, stderr)
		if !ok {
			return 2
		}
		return runDashboard(root, c, dryRun, stdout, stderr)
	case "uninstall":
		dryRun, ok := parseDryRun("uninstall", rest, stderr)
		if !ok {
			return 2
		}
		return uninstall(root, c, dryRun, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "revkit: unknown command %q\n", command)
		printUsage(stderr)
		return 2
	}
}

func install(root string, c catalog.Catalog, update, dryRun bool, stdout, stderr io.Writer) int {
	info, err := host.Current()
	if err != nil {
		fmt.Fprintf(stderr, "revkit: %v\n", err)
		return 2
	}
	fmt.Fprintf(stdout, "Host: %s (%s)\n", info.PrettyName, info.Arch)
	statePath := filepath.Join(root, "state.json")
	st, err := state.Load(statePath)
	if err != nil {
		fmt.Fprintf(stderr, "revkit: %v\n", err)
		return 1
	}
	if _, err := os.Lstat(statePath); err == nil && st.Root == "" {
		fmt.Fprintln(stderr, "revkit: existing state file does not identify a RevKit installation")
		return 1
	} else if err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(stderr, "revkit: inspect installation state: %v\n", err)
		return 1
	}
	if st.Root != "" && filepath.Clean(st.Root) != root {
		fmt.Fprintf(stderr, "revkit: state file belongs to installation root %s\n", st.Root)
		return 1
	}
	if !dryRun {
		if err := ensureRoot(root); err != nil {
			fmt.Fprintf(stderr, "revkit: prepare installation root: %v\n", err)
			return 1
		}
	}
	st.Root, st.Version = root, version
	m := manager.Manager{
		Root: root, Catalog: c, State: &st, Runner: manager.CommandRunner{Stdout: stdout, Stderr: stderr}, Out: stdout, DryRun: dryRun,
	}
	if err := m.Sync(context.Background(), update); err != nil {
		fmt.Fprintf(stderr, "revkit: %v\n", err)
		return 1
	}
	if !dryRun {
		fmt.Fprintf(stdout, "RevKit %s is ready at %s\n", version, root)
	}
	return 0
}

func runDoctor(root string, c catalog.Catalog, stdout, stderr io.Writer) int {
	st, err := state.Load(filepath.Join(root, "state.json"))
	if err != nil {
		fmt.Fprintf(stderr, "revkit: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Installation root: %s\n", root)
	problems := 0
	if st.Root == "" {
		fmt.Fprintln(stdout, "✗ installation root is not recorded; run revkit install")
		problems++
	} else if filepath.Clean(st.Root) != root {
		fmt.Fprintf(stdout, "✗ state belongs to installation root %s\n", st.Root)
		problems++
	}
	if info, err := os.Lstat(root); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		fmt.Fprintln(stdout, "✗ root directory is missing or invalid")
		problems++
	} else {
		fmt.Fprintln(stdout, "✓ root directory exists")
	}
	if cliPath, err := exec.LookPath("revkit"); err != nil {
		fmt.Fprintln(stdout, "✗ revkit is not available on PATH")
		fmt.Fprintln(stdout, "  suggested action: add ~/.local/bin to PATH or start a new login shell")
		problems++
	} else {
		resolved, _ := filepath.EvalSymlinks(cliPath)
		expected, _ := filepath.EvalSymlinks(filepath.Join(root, "bin", "revkit"))
		if expected != "" && resolved == expected {
			fmt.Fprintf(stdout, "✓ revkit on PATH: %s\n", cliPath)
		} else {
			fmt.Fprintf(stdout, "✗ PATH resolves revkit to %s\n", cliPath)
			fmt.Fprintf(stdout, "  expected: %s\n", filepath.Join(root, "bin", "revkit"))
			problems++
		}
	}
	checker := doctor.New(root, st)
	for _, check := range checker.All(c.Tools) {
		printCheck(stdout, check)
		if check.Status != "installed" {
			problems++
		}
	}
	if problems > 0 {
		fmt.Fprintf(stdout, "\nDoctor found %d issue(s).\n", problems)
		return 1
	}
	fmt.Fprintln(stdout, "\nAll catalog tools are available.")
	return 0
}

func runList(root string, c catalog.Catalog, stdout, stderr io.Writer) int {
	st, err := state.Load(filepath.Join(root, "state.json"))
	if err != nil {
		fmt.Fprintf(stderr, "revkit: %v\n", err)
		return 1
	}
	for _, check := range doctor.New(root, st).All(c.Tools) {
		fmt.Fprintf(stdout, "%-16s %-9s %-14s %s\n", check.Tool.ID, check.Status, check.Version, check.Path)
	}
	return 0
}

func runTriage(root, file string, stdout, stderr io.Writer) int {
	if err := ensureRealRoot(root); err != nil {
		fmt.Fprintf(stderr, "revkit: prepare report root: %v\n", err)
		return 1
	}
	if err := ensureDirectoryUnder(root, filepath.Join("workspace", "reports")); err != nil {
		fmt.Fprintf(stderr, "revkit: prepare report directory: %v\n", err)
		return 1
	}
	result, err := (triage.Analyzer{}).Analyze(file)
	if err != nil {
		fmt.Fprintf(stderr, "revkit: triage: %v\n", err)
		return 1
	}
	path, err := triage.SaveReport(filepath.Join(root, "workspace", "reports"), file, result.Markdown)
	if err != nil {
		fmt.Fprintf(stderr, "revkit: save triage report: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Static report saved: %s\nSHA-256: %s\nTarget was NOT executed.\n", path, result.Hash)
	return 0
}

func runDashboard(root string, c catalog.Catalog, dryRun bool, stdout, stderr io.Writer) int {
	st, err := state.Load(filepath.Join(root, "state.json"))
	if err != nil {
		fmt.Fprintf(stderr, "revkit: %v\n", err)
		return 1
	}
	statuses := make(map[string]dashboard.ToolStatus, len(c.Tools))
	for _, check := range doctor.New(root, st).All(c.Tools) {
		statuses[check.Tool.ID] = dashboard.ToolStatus{Status: check.Status, Version: check.Version, Path: check.Path}
	}
	content, err := dashboard.Render(c, statuses)
	if err != nil {
		fmt.Fprintf(stderr, "revkit: render dashboard: %v\n", err)
		return 1
	}
	dest := filepath.Join(root, "dashboard", "index.html")
	if dryRun {
		fmt.Fprintf(stdout, "[dry-run] would write %s\n", dest)
		return 0
	}
	if err := ensureRealRoot(root); err != nil {
		fmt.Fprintf(stderr, "revkit: prepare dashboard root: %v\n", err)
		return 1
	}
	if err := ensureDirectoryUnder(root, "dashboard"); err != nil {
		fmt.Fprintf(stderr, "revkit: prepare dashboard directory: %v\n", err)
		return 1
	}
	if err := dashboard.Write(root, content); err != nil {
		fmt.Fprintf(stderr, "revkit: write dashboard: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Dashboard: %s\n", dest)
	if err := openBrowser(dest); err != nil {
		fmt.Fprintf(stdout, "Open the file in a browser; no compatible opener was found.\n")
	}
	return 0
}

func uninstall(root string, c catalog.Catalog, dryRun bool, stdout, stderr io.Writer) int {
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		fmt.Fprintln(stderr, "revkit: refusing to uninstall from a missing, invalid, or symlinked root")
		return 1
	}
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(stderr, "revkit: locate home directory: %v\n", err)
		return 1
	}
	st, err := state.Load(filepath.Join(root, "state.json"))
	if err != nil {
		fmt.Fprintf(stderr, "revkit: read installation state: %v\n", err)
		return 1
	}
	if st.Root == "" || filepath.Clean(st.Root) != root {
		fmt.Fprintln(stderr, "revkit: refusing to uninstall; state does not identify this installation root")
		return 1
	}
	paths := make([]string, 0, len(c.Tools)+4)
	for _, tool := range c.Tools {
		if tool.Type != "standalone" {
			continue
		}
		if _, managed := st.Tools[tool.ID]; !managed {
			continue
		}
		dir := "cli"
		if tool.Interface != "CLI" {
			dir = "gui"
		}
		paths = append(paths, filepath.Join(root, "tools", dir, tool.ID))
	}
	paths = append(paths,
		filepath.Join(root, "dashboard", "index.html"),
		filepath.Join(root, "state.json"),
		filepath.Join(root, "bin", "revkit"),
	)
	link := filepath.Join(home, ".local", "bin", "revkit")
	if sameSymlinkTarget(link, filepath.Join(root, "bin", "revkit")) {
		if dryRun {
			fmt.Fprintf(stdout, "[dry-run] would remove %s\n", link)
		} else if err := os.Remove(link); err != nil {
			fmt.Fprintf(stderr, "revkit: remove %s: %v\n", link, err)
			return 1
		}
	}
	for _, path := range paths {
		exists, err := inspectManagedPath(root, path)
		if err != nil {
			fmt.Fprintf(stderr, "revkit: inspect %s: %v\n", path, err)
			return 1
		}
		if !exists {
			continue
		}
		if dryRun {
			fmt.Fprintf(stdout, "[dry-run] would remove %s\n", path)
			continue
		}
		if err := os.RemoveAll(path); err != nil {
			fmt.Fprintf(stderr, "revkit: remove %s: %v\n", path, err)
			return 1
		}
	}
	if dryRun {
		fmt.Fprintln(stdout, "Workspace samples, reports, and notes are preserved; APT packages are left installed.")
		return 0
	}
	if err := removeProfileBlock(filepath.Join(home, ".profile")); err != nil {
		fmt.Fprintf(stderr, "revkit: update shell profile: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "RevKit local files and standalone tools were removed.")
	fmt.Fprintln(stdout, "Workspace data and APT packages were preserved.")
	return 0
}

func ensureRoot(root string) error {
	if err := ensureRealRoot(root); err != nil {
		return err
	}
	for _, dir := range []string{"bin", "tools", "tools/gui", "tools/cli", "workspace", "workspace/samples", "workspace/reports", "workspace/notes", "dashboard"} {
		if err := ensureDirectoryUnder(root, dir); err != nil {
			return err
		}
	}
	return fs.WalkDir(revkit.Samples, "samples", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel := strings.TrimPrefix(path, "samples/")
		if path == "samples" {
			return nil
		}
		dest := filepath.Join(root, "workspace", "samples", filepath.FromSlash(rel))
		destRel, err := filepath.Rel(root, dest)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return ensureDirectoryUnder(root, destRel)
		}
		if err := ensureDirectoryUnder(root, filepath.Dir(destRel)); err != nil {
			return err
		}
		data, err := revkit.Samples.ReadFile(path)
		if err != nil {
			return err
		}
		f, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
		if os.IsExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := f.Write(data); err != nil {
			f.Close()
			os.Remove(dest)
			return err
		}
		return f.Close()
	})
}

func ensureRealRoot(root string) error {
	if root == "" {
		return fmt.Errorf("installation root is empty")
	}
	if err := os.MkdirAll(root, 0755); err != nil {
		return err
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a real directory", root)
	}
	return nil
}

func ensureDirectoryUnder(root, relative string) error {
	relative = filepath.Clean(relative)
	if filepath.IsAbs(relative) || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("invalid directory path %q under installation root", relative)
	}
	current := root
	for _, part := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		if err := os.Mkdir(current, 0755); err != nil && !os.IsExist(err) {
			return err
		}
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is not a real directory", current)
		}
	}
	return nil
}

func inspectManagedPath(root, path string) (bool, error) {
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return false, fmt.Errorf("path is outside the installation root")
	}
	parent := filepath.Dir(relative)
	current := root
	if parent != "." {
		for _, part := range strings.Split(parent, string(filepath.Separator)) {
			current = filepath.Join(current, part)
			info, err := os.Lstat(current)
			if os.IsNotExist(err) {
				return false, nil
			}
			if err != nil {
				return false, err
			}
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return false, fmt.Errorf("parent %s is not a real directory", current)
			}
		}
	}
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

func resolveRoot(override string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if override != "" {
		return state.ResolveRoot(override, home)
	}
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(executable)
	if err == nil {
		executable = resolved
	}
	return resolveInstalledRoot(executable, home)
}

func resolveInstalledRoot(executable, home string) (string, error) {
	if filepath.Base(filepath.Dir(executable)) != "bin" {
		return state.ResolveRoot("", home)
	}
	root := filepath.Dir(filepath.Dir(executable))
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	if _, err := os.Lstat(filepath.Join(root, "state.json")); err == nil {
		return root, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	return state.ResolveRoot("", home)
}

func parseDryRun(command string, args []string, stderr io.Writer) (bool, bool) {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	dryRun := flags.Bool("dry-run", false, "show actions without applying them")
	if err := flags.Parse(args); err != nil {
		return false, false
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(stderr, "usage: revkit %s [--dry-run]\n", command)
		return false, false
	}
	return *dryRun, true
}

func openBrowser(file string) error {
	for _, opener := range []struct {
		name string
		args []string
	}{{"xdg-open", []string{file}}, {"gio", []string{"open", file}}} {
		path, err := exec.LookPath(opener.name)
		if err != nil {
			continue
		}
		cmd := exec.Command(path, opener.args...)
		if err := cmd.Start(); err == nil {
			return cmd.Process.Release()
		}
	}
	return errors.New("no browser opener found")
}

func sameSymlinkTarget(link, target string) bool {
	info, err := os.Lstat(link)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return false
	}
	resolvedLink, err := filepath.EvalSymlinks(link)
	if err == nil {
		resolvedTarget, _ := filepath.EvalSymlinks(target)
		return resolvedTarget != "" && resolvedLink == resolvedTarget
	}
	readlink, err := os.Readlink(link)
	if err != nil {
		return false
	}
	if !filepath.IsAbs(readlink) {
		readlink = filepath.Join(filepath.Dir(link), readlink)
	}
	absoluteLink, _ := filepath.Abs(filepath.Clean(readlink))
	absoluteTarget, _ := filepath.Abs(filepath.Clean(target))
	return absoluteLink == absoluteTarget
}

func removeProfileBlock(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	const start, end = "# >>> RevKit PATH >>>", "# <<< RevKit PATH <<<"
	lines := strings.SplitAfter(string(data), "\n")
	var out strings.Builder
	for i := 0; i < len(lines); {
		if strings.TrimSpace(lines[i]) == start {
			endIndex := -1
			for j := i + 1; j < len(lines); j++ {
				if strings.TrimSpace(lines[j]) == end {
					endIndex = j
					break
				}
			}
			if endIndex >= 0 {
				i = endIndex + 1
				continue
			}
		}
		out.WriteString(lines[i])
		i++
	}
	if result := out.String(); result != string(data) {
		return os.WriteFile(path, []byte(result), 0644)
	}
	return nil
}

func printCheck(out io.Writer, check doctor.Check) {
	mark := "✓"
	if check.Status != "installed" {
		mark = "✗"
	}
	fmt.Fprintf(out, "%s %s\n", mark, check.Tool.Name)
	if check.Path != "" {
		fmt.Fprintf(out, "  %s\n", check.Path)
	}
	fmt.Fprintf(out, "  version: %s\n  architecture: %s\n  status: %s\n", check.Version, check.ExpectedArch, check.Status)
	if check.InstalledArch != "" {
		fmt.Fprintf(out, "  installed architecture: %s\n", check.InstalledArch)
	}
	if check.Detail != "" {
		fmt.Fprintf(out, "  %s\n", check.Detail)
	}
	if check.Suggested != "" {
		fmt.Fprintf(out, "  suggested action: %s\n", check.Suggested)
	}
}

func printUsage(out io.Writer) {
	fmt.Fprintln(out, "RevKit — a small reverse-engineering workstation bootstrap")
	fmt.Fprintln(out, "Usage: revkit [--root PATH] COMMAND [OPTIONS]")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Commands:")
	fmt.Fprintln(out, "  revkit install [--dry-run]  Install missing tools and repair broken installs")
	fmt.Fprintln(out, "  revkit update [--dry-run]   Refresh APT metadata and update managed tools")
	fmt.Fprintln(out, "  revkit doctor               Check the root, tools, launchers, versions, and architecture")
	fmt.Fprintln(out, "  revkit list                 List catalog tools and local status")
	fmt.Fprintln(out, "  revkit triage FILE          Write a static-only report; the target is not executed")
	fmt.Fprintln(out, "  revkit dashboard [--dry-run] Generate and open the local dashboard")
	fmt.Fprintln(out, "  revkit uninstall [--dry-run] Remove RevKit files, preserving workspace data")
}
