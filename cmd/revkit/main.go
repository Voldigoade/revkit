package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	revkit "github.com/Voldigoade/revkit"
	"github.com/Voldigoade/revkit/internal/analyze"
	"github.com/Voldigoade/revkit/internal/catalog"
	"github.com/Voldigoade/revkit/internal/dashboard"
	"github.com/Voldigoade/revkit/internal/doctor"
	"github.com/Voldigoade/revkit/internal/host"
	"github.com/Voldigoade/revkit/internal/manager"
	"github.com/Voldigoade/revkit/internal/report"
	"github.com/Voldigoade/revkit/internal/selfupdate"
	"github.com/Voldigoade/revkit/internal/state"
	"github.com/Voldigoade/revkit/internal/tui"
	"github.com/charmbracelet/x/term"
)

var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	if len(os.Args) == 1 && term.IsTerminal(os.Stdin.Fd()) && term.IsTerminal(os.Stdout.Fd()) {
		root, err := resolveRoot("")
		if err != nil {
			fmt.Fprintln(os.Stderr, "revkit:", err)
			os.Exit(2)
		}
		catalogue, err := catalog.Load()
		if err != nil {
			fmt.Fprintln(os.Stderr, "revkit:", err)
			os.Exit(1)
		}
		os.Exit(runTUI(root, catalogue))
	}
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		printUsage(stdout)
		return 0
	}
	rootOverride, args, err := takeRoot(args)
	if err != nil {
		fmt.Fprintln(stderr, "revkit:", err)
		return 2
	}
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}
	command, rest := args[0], args[1:]
	if command == "version" {
		if len(rest) != 0 {
			fmt.Fprintln(stderr, "usage: revkit version")
			return 2
		}
		fmt.Fprintf(stdout, "RevKit %s (%s)\n", version, commit)
		return 0
	}
	root, err := resolveRoot(rootOverride)
	if err != nil {
		fmt.Fprintf(stderr, "revkit: %v\n", err)
		return 2
	}
	catalogue, err := catalog.Load()
	if err != nil {
		fmt.Fprintf(stderr, "revkit: %v\n", err)
		return 1
	}
	switch command {
	case "install":
		dryRun, rest, err := takeFlag(rest, "--dry-run")
		if err != nil || len(rest) != 0 {
			return usageError(stderr, err, "usage: revkit install [--dry-run]")
		}
		return install(root, catalogue, false, dryRun, stdout, stderr)
	case "update":
		dryRun, rest, err := takeFlag(rest, "--dry-run")
		if err != nil || len(rest) != 0 {
			return usageError(stderr, err, "usage: revkit update [--dry-run]")
		}
		return update(root, catalogue, dryRun, stdout, stderr)
	case "__continue-update":
		if len(rest) != 0 {
			return usageError(stderr, nil, "invalid internal update invocation")
		}
		return syncTools(root, catalogue, true, false, stdout, stderr)
	case "doctor":
		machine, rest, err := takeFlag(rest, "--json")
		if err != nil || len(rest) != 0 {
			return usageError(stderr, err, "usage: revkit doctor [--json]")
		}
		return runDoctor(root, catalogue, machine, stdout, stderr)
	case "list":
		machine, rest, err := takeFlag(rest, "--json")
		if err != nil || len(rest) != 0 {
			return usageError(stderr, err, "usage: revkit list [--json]")
		}
		return runList(root, catalogue, machine, stdout, stderr)
	case "analyze":
		machine, rest, err := takeFlag(rest, "--json")
		if err != nil || len(rest) != 1 {
			return usageError(stderr, err, "usage: revkit analyze FILE [--json]")
		}
		return runAnalyze(root, rest[0], machine, stdout, stderr)
	case "dashboard":
		if len(rest) != 0 {
			return usageError(stderr, nil, "usage: revkit dashboard")
		}
		return runDashboard(root, catalogue, true, stdout, stderr)
	case "uninstall":
		dryRun, rest, err := takeFlag(rest, "--dry-run")
		if err != nil || len(rest) != 0 {
			return usageError(stderr, err, "usage: revkit uninstall [--dry-run]")
		}
		return uninstall(root, catalogue, dryRun, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "revkit: unknown command %q\n", command)
		printUsage(stderr)
		return 2
	}
}

func install(root string, catalogue catalog.Catalog, updating, dryRun bool, stdout, stderr io.Writer) int {
	info, err := host.Current()
	if err != nil {
		fmt.Fprintf(stderr, "revkit: %v\n", err)
		return 2
	}
	fmt.Fprintf(stdout, "Host: %s (%s)\n", info.PrettyName, info.Arch)
	st, err := loadState(root)
	if err != nil {
		fmt.Fprintf(stderr, "revkit: %v\n", err)
		return 1
	}
	statePath := filepath.Join(root, "state.json")
	if _, err := os.Lstat(statePath); err == nil && st.Root == "" {
		fmt.Fprintln(stderr, "revkit: existing state file does not identify a RevKit installation")
		return 1
	} else if err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(stderr, "revkit: inspect installation state: %v\n", err)
		return 1
	}
	if st.Root != "" && filepath.Clean(st.Root) != root {
		fmt.Fprintf(stderr, "revkit: state belongs to installation root %s\n", st.Root)
		return 1
	}
	if !dryRun {
		if err := ensureRoot(root); err != nil {
			fmt.Fprintf(stderr, "revkit: prepare installation root: %v\n", err)
			return 1
		}
		executable, err := currentExecutable()
		if err != nil {
			fmt.Fprintf(stderr, "revkit: locate installed executable: %v\n", err)
			return 1
		}
		st.Root, st.Version, st.ExecutablePath = root, version, executable
		if err := state.SaveSelectedRoot(configPath(), root); err != nil {
			fmt.Fprintf(stderr, "revkit: remember installation root: %v\n", err)
			return 1
		}
	}
	if dryRun {
		st.Root, st.Version = root, version
	}
	return syncWithManager(root, catalogue, &st, updating, dryRun, stdout, stderr)
}

func update(root string, catalogue catalog.Catalog, dryRun bool, stdout, stderr io.Writer) int {
	if dryRun {
		fmt.Fprintln(stdout, "Self-update is skipped during a dry run.")
		return syncTools(root, catalogue, true, true, stdout, stderr)
	}
	executable, err := currentExecutable()
	if err != nil {
		fmt.Fprintf(stdout, "Warning: RevKit self-update check skipped: %v\n", err)
	} else {
		updated, updateErr := (selfupdate.Updater{}).Update(context.Background(), version, executable, func(path string) error {
			command := exec.Command(path, "--root", root, "__continue-update")
			command.Stdin, command.Stdout, command.Stderr = os.Stdin, stdout, stderr
			return command.Run()
		})
		if updateErr != nil {
			fmt.Fprintf(stdout, "Warning: RevKit self-update was not applied: %v\n", updateErr)
		} else if updated {
			fmt.Fprintln(stdout, "RevKit self-update completed.")
			return 0
		}
	}
	return syncTools(root, catalogue, true, false, stdout, stderr)
}

func syncTools(root string, catalogue catalog.Catalog, updating, dryRun bool, stdout, stderr io.Writer) int {
	st, err := loadState(root)
	if err != nil {
		fmt.Fprintf(stderr, "revkit: %v\n", err)
		return 1
	}
	if st.Root != "" && filepath.Clean(st.Root) != root {
		fmt.Fprintf(stderr, "revkit: state belongs to installation root %s\n", st.Root)
		return 1
	}
	if !dryRun {
		if err := ensureRoot(root); err != nil {
			fmt.Fprintf(stderr, "revkit: prepare installation root: %v\n", err)
			return 1
		}
	}
	if st.Root == "" {
		st.Root = root
	}
	if !dryRun {
		if err := state.SaveSelectedRoot(configPath(), root); err != nil {
			fmt.Fprintf(stderr, "revkit: remember installation root: %v\n", err)
			return 1
		}
	}
	return syncWithManager(root, catalogue, &st, updating, dryRun, stdout, stderr)
}

func syncWithManager(root string, catalogue catalog.Catalog, st *state.State, updating, dryRun bool, stdout, stderr io.Writer) int {
	if !dryRun {
		st.Root, st.Version = root, version
		if executable, err := currentExecutable(); err == nil {
			st.ExecutablePath = executable
		}
	}
	toolManager := manager.Manager{
		Root: root, Catalog: catalogue, State: st, Runner: manager.CommandRunner{Stdout: stdout, Stderr: stderr}, Out: stdout, DryRun: dryRun,
	}
	if err := toolManager.Sync(context.Background(), updating); err != nil {
		fmt.Fprintf(stderr, "revkit: %v\n", err)
		return 1
	}
	if !dryRun {
		fmt.Fprintf(stdout, "RevKit %s is ready at %s\n", version, root)
	}
	return 0
}

func runDoctor(root string, catalogue catalog.Catalog, machine bool, stdout, stderr io.Writer) int {
	st, err := loadState(root)
	if err != nil {
		fmt.Fprintf(stderr, "revkit: %v\n", err)
		return 1
	}
	checks := doctor.New(root, st).All(catalogue.Tools)
	fatal := 0
	for _, check := range checks {
		if doctor.IsFatal(check) {
			fatal++
		}
	}
	if st.Root == "" || filepath.Clean(st.Root) != root {
		fatal++
	}
	rootInfo, rootErr := os.Lstat(root)
	rootOK := rootErr == nil && rootInfo.IsDir() && rootInfo.Mode()&os.ModeSymlink == 0
	if !rootOK {
		fatal++
	}
	executableOK, executablePath, executableDetail := executableCheck(st.ExecutablePath)
	if !executableOK {
		fatal++
	}
	hostInfo, hostErr := host.Current()
	if hostErr != nil {
		fatal++
	}
	if !machine {
		fmt.Fprintf(stdout, "Installation root: %s\n", root)
		if st.Root == "" {
			fmt.Fprintln(stdout, "✗ installation root is not recorded; run revkit install")
		} else if filepath.Clean(st.Root) != root {
			fmt.Fprintf(stdout, "✗ state belongs to installation root %s\n", st.Root)
		} else {
			fmt.Fprintln(stdout, "✓ installation root is recorded")
		}
		if rootOK {
			fmt.Fprintln(stdout, "✓ root directory exists")
		} else {
			fmt.Fprintln(stdout, "✗ root directory is missing or invalid")
		}
		if executableOK {
			fmt.Fprintf(stdout, "✓ revkit on PATH: %s\n", executablePath)
		} else {
			fmt.Fprintf(stdout, "✗ %s\n", executableDetail)
		}
		if hostErr != nil {
			fmt.Fprintf(stdout, "✗ supported host: %v\n", hostErr)
		} else {
			fmt.Fprintf(stdout, "✓ supported host: %s (%s)\n", hostInfo.PrettyName, hostInfo.Arch)
		}
		for _, check := range checks {
			printCheck(stdout, check)
		}
		if fatal > 0 {
			fmt.Fprintf(stdout, "\nDoctor found %d core issue(s).\n", fatal)
		} else {
			fmt.Fprintln(stdout, "\nCore installation checks passed.")
		}
		if countWarnings(checks) > 0 {
			fmt.Fprintf(stdout, "Optional tool warnings: %d.\n", countWarnings(checks))
		}
		return exitForFatal(fatal)
	}
	type result struct {
		ID              string `json:"id"`
		Name            string `json:"name"`
		Severity        string `json:"severity"`
		Status          string `json:"status"`
		Version         string `json:"version"`
		Path            string `json:"path,omitempty"`
		ExpectedArch    string `json:"expected_architecture"`
		InstalledArch   string `json:"installed_architecture,omitempty"`
		Detail          string `json:"detail,omitempty"`
		SuggestedAction string `json:"suggested_action,omitempty"`
	}
	output := struct {
		SchemaVersion int      `json:"schema_version"`
		Root          string   `json:"root"`
		FatalIssues   int      `json:"fatal_issues"`
		Checks        []result `json:"checks"`
	}{SchemaVersion: 1, Root: root, FatalIssues: fatal}
	for _, check := range checks {
		output.Checks = append(output.Checks, result{
			ID: check.Tool.ID, Name: check.Tool.Name, Severity: check.Severity, Status: check.Status, Version: check.Version, Path: check.Path,
			ExpectedArch: check.ExpectedArch, InstalledArch: check.InstalledArch, Detail: check.Detail, SuggestedAction: check.Suggested,
		})
	}
	if !rootOK {
		output.Checks = append(output.Checks, result{ID: "installation-root-directory", Name: "Installation root directory", Severity: "core", Status: "broken", Version: "n/a", ExpectedArch: "x86_64", Detail: "root directory is missing or invalid"})
	}
	if !executableOK {
		output.Checks = append(output.Checks, result{ID: "revkit-executable", Name: "RevKit executable", Severity: "core", Status: "broken", Version: version, ExpectedArch: "x86_64", Detail: executableDetail, SuggestedAction: "install RevKit into ~/.local/bin and add it to PATH"})
	}
	if hostErr != nil {
		output.Checks = append(output.Checks, result{ID: "host", Name: "Supported host", Severity: "core", Status: "broken", Version: "n/a", ExpectedArch: "x86_64", Detail: hostErr.Error()})
	}
	if st.Root == "" || filepath.Clean(st.Root) != root {
		output.Checks = append(output.Checks, result{ID: "installation-root", Name: "Installation root", Severity: "core", Status: "broken", Version: "n/a", ExpectedArch: "x86_64", Detail: "installation root is not recorded or does not match", SuggestedAction: "run revkit install with the selected root"})
	}
	if err := json.NewEncoder(stdout).Encode(output); err != nil {
		fmt.Fprintf(stderr, "revkit: write doctor JSON: %v\n", err)
		return 1
	}
	return exitForFatal(fatal)
}

func runList(root string, catalogue catalog.Catalog, machine bool, stdout, stderr io.Writer) int {
	st, err := loadState(root)
	if err != nil {
		fmt.Fprintf(stderr, "revkit: %v\n", err)
		return 1
	}
	checks := doctor.New(root, st).All(catalogue.Tools)
	if !machine {
		for _, check := range checks {
			fmt.Fprintf(stdout, "%-16s %-11s %-14s %s\n", check.Tool.ID, check.Status, check.Version, check.Path)
		}
		return 0
	}
	type tool struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Severity  string `json:"severity"`
		Category  string `json:"category"`
		Type      string `json:"type"`
		Interface string `json:"interface"`
		Status    string `json:"status"`
		Version   string `json:"version"`
		Path      string `json:"path,omitempty"`
		Detail    string `json:"detail,omitempty"`
	}
	output := struct {
		SchemaVersion int    `json:"schema_version"`
		Tools         []tool `json:"tools"`
	}{SchemaVersion: 1}
	for _, check := range checks {
		output.Tools = append(output.Tools, tool{
			ID: check.Tool.ID, Name: check.Tool.Name, Severity: check.Severity, Category: check.Tool.CategoryEN, Type: check.Tool.Type,
			Interface: check.Tool.Interface, Status: check.Status, Version: check.Version, Path: check.Path, Detail: check.Detail,
		})
	}
	if err := json.NewEncoder(stdout).Encode(output); err != nil {
		fmt.Fprintf(stderr, "revkit: write list JSON: %v\n", err)
		return 1
	}
	return 0
}

func runAnalyze(root, input string, machine bool, stdout, stderr io.Writer) int {
	if err := ensureRoot(root); err != nil {
		fmt.Fprintf(stderr, "revkit: prepare report root: %v\n", err)
		return 1
	}
	reportsDir := filepath.Join(root, "workspace", "reports")
	if err := ensureDirectoryUnder(root, filepath.Join("workspace", "reports")); err != nil {
		fmt.Fprintf(stderr, "revkit: prepare report directory: %v\n", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	value, err := (analyze.Analyzer{Root: root}).Analyze(ctx, input)
	if err != nil {
		fmt.Fprintf(stderr, "revkit: analyze: %v\n", err)
		return 1
	}
	paths, err := report.Save(reportsDir, value)
	if err != nil {
		fmt.Fprintf(stderr, "revkit: save report: %v\n", err)
		return 1
	}
	value.Metadata.ID = strings.TrimSuffix(filepath.Base(paths.JSON), ".json")
	catalogue, err := catalog.Load()
	if err != nil {
		fmt.Fprintf(stderr, "revkit: load tool catalog: %v\n", err)
		return 1
	}
	if code := runDashboard(root, catalogue, false, io.Discard, stderr); code != 0 {
		return code
	}
	if machine {
		data, err := report.RenderJSON(value)
		if err != nil {
			fmt.Fprintf(stderr, "revkit: render JSON report: %v\n", err)
			return 1
		}
		if _, err := stdout.Write(data); err != nil {
			fmt.Fprintf(stderr, "revkit: write JSON report: %v\n", err)
			return 1
		}
	} else {
		fmt.Fprintf(stdout, "What is it? %s\n\n", value.Summary)
		fmt.Fprintf(stdout, "What that means: %s\n\n", value.Explanation)
		fmt.Fprintln(stdout, "Target was NOT executed.")
		fmt.Fprintf(stdout, "HTML report: %s\nMarkdown:    %s\nJSON:        %s\n", paths.HTML, paths.Markdown, paths.JSON)
		if len(value.NextSteps) > 0 {
			fmt.Fprintf(stdout, "Next step: %s\n", value.NextSteps[0].Action)
		}
	}
	return 0
}

func runDashboard(root string, catalogue catalog.Catalog, open bool, stdout, stderr io.Writer) int {
	if err := ensureRoot(root); err != nil {
		fmt.Fprintf(stderr, "revkit: prepare dashboard root: %v\n", err)
		return 1
	}
	if err := ensureDirectoryUnder(root, "workspace/reports"); err != nil {
		fmt.Fprintf(stderr, "revkit: prepare report directory: %v\n", err)
		return 1
	}
	if err := ensureDirectoryUnder(root, "dashboard"); err != nil {
		fmt.Fprintf(stderr, "revkit: prepare dashboard directory: %v\n", err)
		return 1
	}
	st, err := loadState(root)
	if err != nil {
		fmt.Fprintf(stderr, "revkit: %v\n", err)
		return 1
	}
	statuses := make(map[string]dashboard.ToolStatus, len(catalogue.Tools))
	for _, check := range doctor.New(root, st).All(catalogue.Tools) {
		statuses[check.Tool.ID] = dashboard.ToolStatus{Status: check.Status, Version: check.Version, Path: check.Path}
	}
	reportsDir := filepath.Join(root, "workspace", "reports")
	reports, err := report.LoadIndex(reportsDir)
	if err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(stderr, "revkit: read reports: %v\n", err)
		return 1
	}
	content, err := dashboard.Render(catalogue, statuses, reports)
	if err != nil {
		fmt.Fprintf(stderr, "revkit: render dashboard: %v\n", err)
		return 1
	}
	if err := dashboard.Write(root, content); err != nil {
		fmt.Fprintf(stderr, "revkit: write dashboard: %v\n", err)
		return 1
	}
	dest := filepath.Join(root, "dashboard", "index.html")
	fmt.Fprintf(stdout, "Dashboard: %s\n", dest)
	if open {
		if err := openBrowser(dest); err != nil {
			fmt.Fprintln(stdout, "Open the file in a browser; no compatible opener was found.")
		}
	}
	return 0
}

func runTUI(root string, catalogue catalog.Catalog) int {
	if err := ensureRoot(root); err != nil {
		fmt.Fprintln(os.Stderr, "revkit:", err)
		return 1
	}
	index, err := report.LoadIndex(filepath.Join(root, "workspace", "reports"))
	if err != nil && !os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, "revkit:", err)
		return 1
	}
	options := tui.Options{}
	for _, item := range index {
		options.Reports = append(options.Reports, tui.Item{
			Title: item.Filename, Detail: item.Format + " " + item.Architecture,
			Path: filepath.Join(root, "workspace", "reports", item.HTML),
		})
	}
	for _, tool := range catalogue.Tools {
		options.Tools = append(options.Tools, tui.Item{Title: tool.Name, Detail: tool.Interface + " · " + tool.Severity})
	}
	selected, err := tui.Run(options)
	if err != nil {
		fmt.Fprintln(os.Stderr, "revkit:", err)
		return 1
	}
	stdout, stderr := os.Stdout, os.Stderr
	switch selected.Action {
	case "analyze":
		return runAnalyze(root, selected.Target, false, stdout, stderr)
	case "open-report":
		if err := openBrowser(selected.Target); err != nil {
			fmt.Fprintln(stderr, "revkit:", err)
			return 1
		}
		return 0
	case "update":
		return update(root, catalogue, false, stdout, stderr)
	case "doctor":
		return runDoctor(root, catalogue, false, stdout, stderr)
	case "dashboard":
		return runDashboard(root, catalogue, true, stdout, stderr)
	default:
		return 0
	}
}

func uninstall(root string, catalogue catalog.Catalog, dryRun bool, stdout, stderr io.Writer) int {
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		fmt.Fprintln(stderr, "revkit: refusing to uninstall from a missing, invalid, or symlinked root")
		return 1
	}
	st, err := loadState(root)
	if err != nil {
		fmt.Fprintf(stderr, "revkit: read installation state: %v\n", err)
		return 1
	}
	if st.Root == "" || filepath.Clean(st.Root) != root {
		fmt.Fprintln(stderr, "revkit: refusing to uninstall; state does not identify this installation root")
		return 1
	}
	paths := make([]string, 0, len(catalogue.Tools)+3)
	for _, tool := range catalogue.Tools {
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
	paths = append(paths, filepath.Join(root, "dashboard", "index.html"), filepath.Join(root, "state.json"))
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
	config := configPath()
	if selected, err := state.LoadSelectedRoot(config); err == nil && filepath.Clean(selected) == root {
		if dryRun {
			fmt.Fprintf(stdout, "[dry-run] would remove %s\n", config)
		} else if err := os.Remove(config); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(stderr, "revkit: remove selected-root configuration: %v\n", err)
			return 1
		}
	}
	executable, _ := currentExecutable()
	if executable != "" && st.ExecutablePath != "" && filepath.Clean(st.ExecutablePath) == executable {
		if info, err := os.Lstat(executable); err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
			if dryRun {
				fmt.Fprintf(stdout, "[dry-run] would remove %s\n", executable)
			} else if err := os.Remove(executable); err != nil {
				fmt.Fprintf(stderr, "revkit: remove RevKit executable: %v\n", err)
				return 1
			}
		}
	}
	if dryRun {
		fmt.Fprintln(stdout, "Workspace samples, reports, and notes are preserved; APT packages are left installed.")
		return 0
	}
	fmt.Fprintln(stdout, "RevKit files and standalone tools were removed.")
	fmt.Fprintln(stdout, "Workspace data and APT packages were preserved.")
	return 0
}

func ensureRoot(root string) error {
	if err := ensureRealRoot(root); err != nil {
		return err
	}
	for _, dir := range []string{"tools", "tools/gui", "tools/cli", "workspace", "workspace/samples", "workspace/reports", "workspace/notes", "dashboard"} {
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
		file, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
		if os.IsExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := file.Write(data); err != nil {
			file.Close()
			os.Remove(dest)
			return err
		}
		return file.Close()
	})
}

func ensureRealRoot(root string) error {
	if root == "" {
		return errors.New("installation root is empty")
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
		return false, errors.New("path is outside the installation root")
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
	selected, err := state.LoadSelectedRoot(state.ConfigPath(home, os.Getenv("XDG_CONFIG_HOME")))
	if err != nil {
		return "", err
	}
	if selected != "" {
		return selected, nil
	}
	return state.ResolveRoot("", home)
}

func configPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return state.ConfigPath(home, os.Getenv("XDG_CONFIG_HOME"))
}

func currentExecutable() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	return filepath.Abs(filepath.Clean(path))
}

func loadState(root string) (state.State, error) {
	path := filepath.Join(root, "state.json")
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return state.State{Tools: map[string]state.ToolState{}}, nil
	}
	if err != nil {
		return state.State{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return state.State{}, errors.New("installation state is not a regular file")
	}
	return state.Load(path)
}

func takeRoot(args []string) (string, []string, error) {
	if len(args) == 0 {
		return "", args, nil
	}
	if args[0] == "--root" {
		if len(args) < 3 || args[1] == "" {
			return "", nil, errors.New("--root requires a path before the command")
		}
		return args[1], args[2:], nil
	}
	if strings.HasPrefix(args[0], "--root=") {
		root := strings.TrimPrefix(args[0], "--root=")
		if root == "" || len(args) < 2 {
			return "", nil, errors.New("--root requires a path before the command")
		}
		return root, args[1:], nil
	}
	return "", args, nil
}

func takeFlag(args []string, name string) (bool, []string, error) {
	var found bool
	remaining := make([]string, 0, len(args))
	for _, arg := range args {
		if arg == name {
			if found {
				return false, nil, fmt.Errorf("%s may only be specified once", name)
			}
			found = true
			continue
		}
		if strings.HasPrefix(arg, name+"=") {
			return false, nil, fmt.Errorf("%s does not take a value", name)
		}
		remaining = append(remaining, arg)
	}
	return found, remaining, nil
}

func usageError(stderr io.Writer, err error, usage string) int {
	if err != nil {
		fmt.Fprintf(stderr, "revkit: %v\n", err)
	}
	fmt.Fprintln(stderr, usage)
	return 2
}

func executableCheck(recorded string) (bool, string, string) {
	if recorded == "" {
		return false, "", "executable path is not recorded; run revkit install"
	}
	path, err := exec.LookPath("revkit")
	if err != nil {
		return false, "", "revkit is not available on PATH; add ~/.local/bin to PATH"
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		resolved = path
	}
	if filepath.Clean(resolved) != filepath.Clean(recorded) {
		return false, path, fmt.Sprintf("PATH resolves revkit to %s; expected %s", path, recorded)
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return false, path, "RevKit executable is missing or not executable"
	}
	return true, path, ""
}

func printCheck(out io.Writer, check doctor.Check) {
	mark := "✓"
	if check.Status != "installed" {
		if check.Severity == "optional" {
			mark = "⚠"
		} else {
			mark = "✗"
		}
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

func countWarnings(checks []doctor.Check) int {
	count := 0
	for _, check := range checks {
		if check.Severity == "optional" && check.Status != "installed" {
			count++
		}
	}
	return count
}

func exitForFatal(fatal int) int {
	if fatal > 0 {
		return 1
	}
	return 0
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
		command := exec.Command(path, opener.args...)
		if err := command.Start(); err == nil {
			return command.Process.Release()
		}
	}
	return errors.New("no browser opener found")
}

func printUsage(out io.Writer) {
	fmt.Fprintln(out, "RevKit")
	fmt.Fprintln(out, "Usage: revkit [--root PATH] COMMAND [OPTIONS]")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Commands:")
	fmt.Fprintln(out, "  revkit install [--dry-run]   Install missing tools and repair broken installs")
	fmt.Fprintln(out, "  revkit update [--dry-run]    Update RevKit and managed tools")
	fmt.Fprintln(out, "  revkit doctor [--json]       Check the root and tool installations")
	fmt.Fprintln(out, "  revkit list [--json]         List catalog tools and local status")
	fmt.Fprintln(out, "  revkit analyze FILE [--json] Analyze a file without executing it")
	fmt.Fprintln(out, "  revkit dashboard             Generate and open the local dashboard")
	fmt.Fprintln(out, "  revkit version               Show the installed version")
	fmt.Fprintln(out, "  revkit uninstall [--dry-run] Remove RevKit files, preserving workspace data")
}
