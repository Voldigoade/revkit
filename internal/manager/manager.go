package manager

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Voldigoade/revkit/internal/catalog"
	"github.com/Voldigoade/revkit/internal/doctor"
	"github.com/Voldigoade/revkit/internal/state"
)

const maxReleaseAsset = 2 << 30

type Runner interface {
	Run(context.Context, string, ...string) error
	Output(context.Context, string, ...string) ([]byte, error)
}

type CommandRunner struct {
	Stdout io.Writer
	Stderr io.Writer
	DryRun bool
}

func (r CommandRunner) Run(ctx context.Context, name string, args ...string) error {
	if r.DryRun {
		fmt.Fprintf(r.Stdout, "[dry-run] %s\n", displayCommand(name, args))
		return nil
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, r.Stdout, r.Stderr
	return cmd.Run()
}

func (r CommandRunner) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}

type Manager struct {
	Root       string
	Catalog    catalog.Catalog
	State      *state.State
	Runner     Runner
	HTTPClient *http.Client
	APIBase    string
	Now        func() time.Time
	Out        io.Writer
	DryRun     bool
}

type release struct {
	TagName string          `json:"tag_name"`
	Assets  []catalog.Asset `json:"assets"`
}

type packageInfo struct {
	Installed bool
	Version   string
	Candidate string
}

func PackageAction(installed, broken bool, current, candidate string) string {
	if !installed {
		return "install"
	}
	if broken {
		return "repair"
	}
	if candidate != "" && candidate != "(none)" && current != "" && state.CompareVersions(current, candidate) < 0 {
		return "update"
	}
	return "none"
}

func (m *Manager) Sync(ctx context.Context, update bool) error {
	if m.Root == "" {
		return errors.New("installation root is empty")
	}
	if m.State == nil {
		m.State = &state.State{Tools: map[string]state.ToolState{}}
	}
	if m.State.Tools == nil {
		m.State.Tools = map[string]state.ToolState{}
	}
	if m.Runner == nil {
		m.Runner = CommandRunner{Stdout: m.out(), Stderr: m.out()}
	}
	if m.Now == nil {
		m.Now = time.Now
	}
	m.State.Root = m.Root
	if !m.DryRun {
		if err := state.Save(filepath.Join(m.Root, "state.json"), *m.State); err != nil {
			return fmt.Errorf("save installation state: %w", err)
		}
	}
	unavailable, err := m.syncPackages(ctx, update)
	if err != nil {
		return err
	}
	if err := m.syncStandalone(ctx, update, unavailable); err != nil {
		return err
	}
	m.State.Root = m.Root
	if !m.DryRun {
		if err := state.Save(filepath.Join(m.Root, "state.json"), *m.State); err != nil {
			return fmt.Errorf("save installation state: %w", err)
		}
	}
	return nil
}

func (m *Manager) syncPackages(ctx context.Context, update bool) (map[string]bool, error) {
	now := m.Now()
	refresh := update || m.State.APTUpdated.IsZero() || now.Sub(m.State.APTUpdated) >= state.CheckInterval
	if refresh {
		if err := m.aptRun(ctx, "update"); err != nil {
			return nil, fmt.Errorf("refresh APT metadata: %w", err)
		}
		if !m.DryRun {
			m.State.APTUpdated = now
		}
	}

	packages := m.Catalog.Packages()
	infos := make(map[string]packageInfo, len(packages))
	corePackages := make(map[string]bool, len(packages))
	for _, tool := range m.Catalog.Tools {
		if tool.Severity == "core" {
			if tool.Type == "system" {
				corePackages[tool.Package] = true
			}
			for _, pkg := range tool.RequiresPackage {
				corePackages[pkg] = true
			}
		}
	}
	for _, pkg := range packages {
		info, err := m.packageInfo(ctx, pkg)
		if err != nil {
			return nil, fmt.Errorf("inspect APT package %s: %w", pkg, err)
		}
		infos[pkg] = info
	}
	checker := doctor.New(m.Root, *m.State)
	checker.PackageInstalled = func(pkg string) (bool, error) { return infos[pkg].Installed, nil }
	reinstall := map[string]bool{}
	for _, tool := range m.Catalog.Tools {
		if tool.Type != "system" || !infos[tool.Package].Installed {
			continue
		}
		if checker.Tool(tool).Status == "broken" {
			reinstall[tool.Package] = true
		}
	}
	var missing, outdated, broken []string
	unavailable := map[string]bool{}
	for _, pkg := range packages {
		info := infos[pkg]
		if !info.Installed && (info.Candidate == "" || info.Candidate == "(none)") {
			unavailable[pkg] = true
			if corePackages[pkg] {
				return nil, fmt.Errorf("core APT package %s is unavailable in configured repositories", pkg)
			}
			fmt.Fprintf(m.out(), "⚠ Optional APT package %s is unavailable in configured repositories; skipping it.\n", pkg)
			continue
		}
		switch PackageAction(info.Installed, reinstall[pkg], info.Version, info.Candidate) {
		case "install":
			missing = append(missing, pkg)
		case "update":
			outdated = append(outdated, pkg)
		case "repair":
			broken = append(broken, pkg)
		}
	}
	for _, group := range []struct {
		args []string
		pkgs map[bool][]string
	}{
		{args: []string{"install", "-y"}, pkgs: splitPackageSeverity(missing, corePackages)},
		{args: []string{"install", "-y", "--only-upgrade"}, pkgs: splitPackageSeverity(outdated, corePackages)},
		{args: []string{"install", "-y", "--reinstall"}, pkgs: splitPackageSeverity(broken, corePackages)},
	} {
		for _, core := range []bool{true, false} {
			pkgs := group.pkgs[core]
			if len(pkgs) == 0 {
				continue
			}
			sort.Strings(pkgs)
			args := append(group.args, pkgs...)
			if err := m.aptRun(ctx, args...); err != nil {
				if core {
					return nil, fmt.Errorf("install core APT packages %s: %w", strings.Join(pkgs, ", "), err)
				}
				fmt.Fprintf(m.out(), "⚠ Optional APT packages %s could not be installed: %v\n", strings.Join(pkgs, ", "), err)
				if len(group.args) == 2 {
					for _, pkg := range pkgs {
						unavailable[pkg] = true
					}
				}
			}
		}
	}
	if len(missing)+len(outdated)+len(broken) == 0 && len(unavailable) == 0 {
		fmt.Fprintln(m.out(), "APT tools are installed and up to date.")
	}
	return unavailable, nil
}

func splitPackageSeverity(packages []string, corePackages map[string]bool) map[bool][]string {
	result := map[bool][]string{true: {}, false: {}}
	for _, pkg := range packages {
		result[corePackages[pkg]] = append(result[corePackages[pkg]], pkg)
	}
	return result
}

func (m *Manager) packageInfo(ctx context.Context, pkg string) (packageInfo, error) {
	data, err := m.Runner.Output(ctx, "dpkg-query", "-W", "--showformat=${db:Status-Status}\t${Version}", "--", pkg)
	info := packageInfo{}
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
			return info, err
		}
	} else {
		fields := strings.SplitN(strings.TrimSpace(string(data)), "\t", 2)
		if len(fields) == 2 && fields[0] == "installed" {
			info.Installed, info.Version = true, fields[1]
		}
	}
	data, err = m.Runner.Output(ctx, "apt-cache", "policy", pkg)
	if err != nil {
		return info, err
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Candidate:") {
			info.Candidate = strings.TrimSpace(strings.TrimPrefix(line, "Candidate:"))
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return info, err
	}
	if info.Installed && info.Candidate != "" && info.Candidate != "(none)" && info.Candidate != info.Version {
		_, compareErr := m.Runner.Output(ctx, "dpkg", "--compare-versions", info.Version, "lt", info.Candidate)
		if compareErr == nil {
			return info, nil
		}
		var exitErr *exec.ExitError
		if errors.As(compareErr, &exitErr) && exitErr.ExitCode() == 1 {
			info.Candidate = info.Version
		} else {
			return info, compareErr
		}
	}
	return info, nil
}

func (m *Manager) aptRun(ctx context.Context, args ...string) error {
	command, prefix := "apt-get", []string{}
	if os.Geteuid() != 0 {
		command, prefix = "sudo", []string{"apt-get"}
	}
	if m.DryRun {
		fmt.Fprintf(m.out(), "[dry-run] %s\n", displayCommand(command, append(prefix, args...)))
		return nil
	}
	return m.Runner.Run(ctx, command, append(prefix, args...)...)
}

func (m *Manager) syncStandalone(ctx context.Context, update bool, unavailable map[string]bool) error {
	checker := doctor.New(m.Root, *m.State)
	now := m.Now()
	for _, tool := range m.Catalog.Tools {
		if tool.Type != "standalone" {
			continue
		}
		var missingDependencies []string
		for _, pkg := range tool.RequiresPackage {
			if unavailable[pkg] {
				missingDependencies = append(missingDependencies, pkg)
			}
		}
		if len(missingDependencies) > 0 {
			fmt.Fprintf(m.out(), "⚠ %s requires APT package(s) that are unavailable or could not be installed (%s); skipping release management.\n", tool.Name, strings.Join(missingDependencies, ", "))
			continue
		}
		check := checker.Tool(tool)
		previous := m.State.Tools[tool.ID]
		stale := state.NeedsCheck(now, previous.CheckedAt)
		if check.Status == "installed" && !update && !stale {
			fmt.Fprintf(m.out(), "✓ %s - installed, checked %s\n", tool.Name, previous.Version)
			continue
		}
		if m.DryRun {
			fmt.Fprintf(m.out(), "[dry-run] would verify the official amd64 release and install/repair %s from %s\n", tool.Name, tool.OfficialSource)
			continue
		}
		release, err := m.fetchLatest(ctx, tool)
		if err != nil {
			if tool.Severity == "optional" {
				fmt.Fprintf(m.out(), "⚠ Optional tool %s could not be checked: %v\n", tool.Name, err)
				continue
			}
			return fmt.Errorf("check %s release: %w", tool.Name, err)
		}
		version := strings.TrimPrefix(release.TagName, "v")
		if version == "" {
			if tool.Severity == "optional" {
				fmt.Fprintf(m.out(), "⚠ Optional tool %s release has no version tag; skipping it.\n", tool.Name)
				continue
			}
			return fmt.Errorf("%s release has no tag", tool.Name)
		}
		if check.Status == "installed" && previous.Version != "" && state.CompareVersions(previous.Version, version) > 0 {
			previous.CheckedAt = now
			m.State.Tools[tool.ID] = previous
			checker.State = *m.State
			fmt.Fprintf(m.out(), "✓ %s - installed %s is newer than upstream %s; keeping it\n", tool.Name, previous.Version, version)
			continue
		}
		asset, err := catalog.SelectAsset(tool, release.Assets, "amd64")
		if err != nil {
			if tool.Severity == "optional" {
				fmt.Fprintf(m.out(), "⚠ Optional tool %s has no verified amd64 release asset: %v\n", tool.Name, err)
				continue
			}
			return err
		}
		action := state.Decide(check.Status == "installed", check.Status == "broken", previous.Version, version)
		if check.Status == "installed" && previous.Version == "" {
			action = state.ActionRepair
		}
		if action == state.ActionNone && previous.Digest == asset.Digest {
			previous.CheckedAt = now
			m.State.Tools[tool.ID] = previous
			fmt.Fprintf(m.out(), "✓ %s - up to date (%s)\n", tool.Name, version)
			checker.State = *m.State
			continue
		}
		if action == state.ActionNone && previous.Digest != asset.Digest {
			action = state.ActionRepair
		}
		fmt.Fprintf(m.out(), "%s %s (%s)\n", action, tool.Name, version)
		path, err := m.installAsset(ctx, tool, asset)
		if err != nil {
			if tool.Severity == "optional" {
				fmt.Fprintf(m.out(), "⚠ Optional tool %s could not be installed: %v\n", tool.Name, err)
				continue
			}
			return fmt.Errorf("install %s: %w", tool.Name, err)
		}
		m.State.Tools[tool.ID] = state.ToolState{Version: version, Digest: asset.Digest, Path: path, CheckedAt: now}
		if err := state.Save(filepath.Join(m.Root, "state.json"), *m.State); err != nil {
			return fmt.Errorf("save %s installation state: %w", tool.Name, err)
		}
		checker.State = *m.State
	}
	return nil
}

func (m *Manager) fetchLatest(ctx context.Context, tool catalog.Tool) (release, error) {
	base := m.APIBase
	if base == "" {
		base = "https://api.github.com"
	}
	repo, err := catalog.GitHubReleaseRepo(tool.OfficialSource)
	if err != nil {
		return release{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/repos/"+repo+"/releases/latest", nil)
	if err != nil {
		return release{}, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "RevKit")
	client := m.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	response, err := client.Do(request)
	if err != nil {
		return release{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return release{}, fmt.Errorf("GitHub API returned %s", response.Status)
	}
	var result release
	if err := json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(&result); err != nil {
		return release{}, fmt.Errorf("decode GitHub release metadata: %w", err)
	}
	return result, nil
}

func (m *Manager) installAsset(ctx context.Context, tool catalog.Tool, asset catalog.Asset) (string, error) {
	assetURL, err := url.Parse(asset.URL)
	if err != nil || assetURL.Scheme != "https" || assetURL.Host != "github.com" || assetURL.User != nil || assetURL.Port() != "" {
		return "", fmt.Errorf("release asset URL is not an official GitHub HTTPS URL")
	}
	u, err := http.NewRequestWithContext(ctx, http.MethodGet, asset.URL, nil)
	if err != nil {
		return "", err
	}
	client := m.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Minute}
	}
	client = downloadClient(client)
	response, err := client.Do(u)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download returned %s", response.Status)
	}
	if response.Request == nil || !trustedDownloadHost(response.Request.URL) {
		return "", fmt.Errorf("download redirected to an untrusted host")
	}
	if response.ContentLength > maxReleaseAsset {
		return "", fmt.Errorf("release asset exceeds the 2 GiB limit")
	}
	parent := m.toolParent(tool)
	if err := os.MkdirAll(parent, 0755); err != nil {
		return "", err
	}
	archive, err := os.CreateTemp(parent, ".revkit-download-*.tmp")
	if err != nil {
		return "", err
	}
	archivePath := archive.Name()
	defer os.Remove(archivePath)
	h := sha256.New()
	written, err := io.Copy(io.MultiWriter(archive, h), io.LimitReader(response.Body, maxReleaseAsset+1))
	if err != nil {
		archive.Close()
		return "", err
	}
	if written > maxReleaseAsset {
		archive.Close()
		return "", fmt.Errorf("release asset exceeds the 2 GiB limit")
	}
	if err := archive.Sync(); err != nil {
		archive.Close()
		return "", err
	}
	if err := archive.Close(); err != nil {
		return "", err
	}
	want := strings.TrimPrefix(strings.ToLower(asset.Digest), "sha256:")
	if hex.EncodeToString(h.Sum(nil)) != want {
		return "", fmt.Errorf("release asset SHA-256 mismatch")
	}
	stage, err := os.MkdirTemp(parent, ".revkit-stage-"+tool.ID+"-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(stage)
	switch tool.AssetFormat {
	case "zip":
		err = extractZip(archivePath, stage)
	case "tar.xz":
		err = extractTarXZ(ctx, archivePath, stage)
	case "appimage":
		dest := filepath.Join(stage, tool.Executable)
		err = copyFile(archivePath, dest, 0755)
	default:
		err = fmt.Errorf("unsupported archive format %q", tool.AssetFormat)
	}
	if err != nil {
		return "", err
	}
	launcher := findNamed(stage, tool.Executable)
	if launcher == "" {
		return "", fmt.Errorf("release does not contain expected launcher %q", tool.Executable)
	}
	if err := os.Chmod(launcher, 0755); err != nil {
		return "", err
	}
	arch, isELF, err := binaryArch(launcher)
	if err != nil {
		return "", err
	}
	if isELF && arch != "x86_64" {
		return "", fmt.Errorf("release launcher architecture is %s; expected x86_64", arch)
	}
	final := filepath.Join(parent, tool.ID)
	if err := replaceDirectory(stage, final); err != nil {
		return "", err
	}
	launcherRelative, err := filepath.Rel(stage, launcher)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(m.Root, filepath.Join(final, launcherRelative))
	if err != nil {
		return "", err
	}
	return relative, nil
}

func downloadClient(client *http.Client) *http.Client {
	copy := *client
	previous := client.CheckRedirect
	copy.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if !trustedDownloadHost(request.URL) {
			return fmt.Errorf("download redirected to an untrusted host")
		}
		if previous != nil {
			return previous(request, via)
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
	return &copy
}

func (m *Manager) toolParent(tool catalog.Tool) string {
	dir := "cli"
	if tool.Interface != "CLI" {
		dir = "gui"
	}
	return filepath.Join(m.Root, "tools", dir)
}

func (m *Manager) out() io.Writer {
	if m.Out == nil {
		return os.Stdout
	}
	return m.Out
}

func displayCommand(name string, args []string) string {
	all := append([]string{name}, args...)
	for i := range all {
		if strings.ContainsAny(all[i], " \t\n'\"") {
			all[i] = fmt.Sprintf("%q", all[i])
		}
	}
	return strings.Join(all, " ")
}

func trustedDownloadHost(u *url.URL) bool {
	if u == nil || u.Scheme != "https" || u.User != nil || u.Port() != "" {
		return false
	}
	switch strings.ToLower(u.Hostname()) {
	case "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com", "github-releases.githubusercontent.com":
		return true
	default:
		return false
	}
}

func replaceDirectory(stage, final string) error {
	backup := ""
	if _, err := os.Lstat(final); err == nil {
		parent := filepath.Dir(final)
		placeholder, err := os.MkdirTemp(parent, ".revkit-old-")
		if err != nil {
			return err
		}
		if err := os.Remove(placeholder); err != nil {
			return err
		}
		backup = placeholder
		if err := os.Rename(final, backup); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(stage, final); err != nil {
		if backup != "" {
			_ = os.Rename(backup, final)
		}
		return err
	}
	if backup != "" {
		if err := os.RemoveAll(backup); err != nil {
			return fmt.Errorf("remove previous tool release: %w", err)
		}
	}
	return nil
}
