package selfupdate

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	owner         = "Voldigoade"
	repository    = "revkit"
	binaryName    = "revkit-linux-amd64"
	checksumsName = "SHA256SUMS"
	maxBinary     = 64 << 20
)

var releaseTag = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)

type Updater struct {
	Client *http.Client
}

type release struct {
	TagName string  `json:"tag_name"`
	Assets  []asset `json:"assets"`
}

type asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

func ShouldUpdate(current, latest string) bool {
	if !releaseTag.MatchString(latest) || !releaseTag.MatchString(current) {
		return false
	}
	return compareVersions(current, latest) < 0
}

func compareVersions(left, right string) int {
	var a, b [3]uint64
	if _, err := fmt.Sscanf(strings.TrimPrefix(left, "v"), "%d.%d.%d", &a[0], &a[1], &a[2]); err != nil {
		return 0
	}
	if _, err := fmt.Sscanf(strings.TrimPrefix(right, "v"), "%d.%d.%d", &b[0], &b[1], &b[2]); err != nil {
		return 0
	}
	for index := range a {
		if a[index] < b[index] {
			return -1
		}
		if a[index] > b[index] {
			return 1
		}
	}
	return 0
}

func VerifyChecksum(data []byte, sums, name string) (string, error) {
	var expected string
	scanner := bufio.NewScanner(strings.NewReader(sums))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 || strings.TrimPrefix(fields[1], "*") != name {
			continue
		}
		if expected != "" {
			return "", fmt.Errorf("checksum file has duplicate entries for %s", name)
		}
		if len(fields[0]) != sha256.Size*2 {
			return "", fmt.Errorf("checksum for %s has an invalid length", name)
		}
		if _, err := hex.DecodeString(fields[0]); err != nil {
			return "", fmt.Errorf("checksum for %s is not hexadecimal", name)
		}
		expected = strings.ToLower(fields[0])
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if expected == "" {
		return "", fmt.Errorf("checksum file does not list %s", name)
	}
	actual := sha256.Sum256(data)
	if hex.EncodeToString(actual[:]) != expected {
		return "", fmt.Errorf("SHA-256 mismatch for %s", name)
	}
	return expected, nil
}

func (u Updater) Update(ctx context.Context, current, executable string, continueUpdate func(string) error) (bool, error) {
	release, err := u.latest(ctx)
	if err != nil {
		return false, err
	}
	if !releaseTag.MatchString(release.TagName) {
		return false, fmt.Errorf("latest GitHub release has an invalid stable version tag %q", release.TagName)
	}
	if !ShouldUpdate(current, release.TagName) {
		return false, nil
	}
	binary, err := releaseAsset(release.Assets, binaryName, release.TagName)
	if err != nil {
		return false, err
	}
	sums, err := releaseAsset(release.Assets, checksumsName, release.TagName)
	if err != nil {
		return false, err
	}
	checksumData, err := u.download(ctx, sums.URL, 1<<20)
	if err != nil {
		return false, fmt.Errorf("download release checksums: %w", err)
	}
	data, err := u.download(ctx, binary.URL, maxBinary)
	if err != nil {
		return false, fmt.Errorf("download RevKit release: %w", err)
	}
	if _, err := VerifyChecksum(data, string(checksumData), binaryName); err != nil {
		return false, err
	}
	if err := validateAMD64(data); err != nil {
		return false, err
	}
	if err := atomicReplace(executable, data, continueUpdate); err != nil {
		return false, err
	}
	return true, nil
}

func (u Updater) latest(ctx context.Context) (release, error) {
	requestURL := "https://api.github.com/repos/" + owner + "/" + repository + "/releases/latest"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return release{}, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "RevKit")
	client := u.client(30 * time.Second)
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if request.URL.Scheme != "https" || strings.ToLower(request.URL.Hostname()) != "api.github.com" {
			return errors.New("GitHub release metadata redirected to an untrusted host")
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 GitHub API redirects")
		}
		return nil
	}
	response, err := client.Do(request)
	if err != nil {
		return release{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return release{}, fmt.Errorf("GitHub release check returned %s", response.Status)
	}
	var latest release
	if err := json.NewDecoder(io.LimitReader(response.Body, 2<<20)).Decode(&latest); err != nil {
		return release{}, fmt.Errorf("decode GitHub release: %w", err)
	}
	return latest, nil
}

func releaseAsset(assets []asset, name, tag string) (asset, error) {
	var found asset
	for _, item := range assets {
		if item.Name != name {
			continue
		}
		if found.Name != "" {
			return asset{}, fmt.Errorf("release contains duplicate %s assets", name)
		}
		if !officialAssetURL(item.URL, name, tag) {
			return asset{}, fmt.Errorf("release asset %s does not use its official GitHub download URL", name)
		}
		found = item
	}
	if found.Name == "" {
		return asset{}, fmt.Errorf("release is missing %s", name)
	}
	return found, nil
}

func officialAssetURL(raw, name, tag string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || strings.ToLower(u.Hostname()) != "github.com" || u.User != nil || u.Port() != "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	want := "/" + owner + "/" + repository + "/releases/download/" + tag + "/" + name
	return u.Path == want
}

func (u Updater) download(ctx context.Context, raw string, max int64) ([]byte, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || strings.ToLower(parsed.Hostname()) != "github.com" || parsed.User != nil || parsed.Port() != "" {
		return nil, errors.New("download URL is not an official GitHub HTTPS URL")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, err
	}
	client := u.client(2 * time.Minute)
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if trustedDownloadURL(request.URL) {
			return nil
		}
		return fmt.Errorf("release download redirected to untrusted host %q", request.URL.Hostname())
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download returned %s", response.Status)
	}
	if response.Request == nil {
		return nil, errors.New("download response has no request context")
	}
	if response.ContentLength > max {
		return nil, fmt.Errorf("download exceeds the %d-byte limit", max)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("download exceeds the %d-byte limit", max)
	}
	return data, nil
}

func (u Updater) client(timeout time.Duration) *http.Client {
	if u.Client != nil {
		copy := *u.Client
		if copy.Timeout == 0 {
			copy.Timeout = timeout
		}
		return &copy
	}
	return &http.Client{Timeout: timeout}
}

func validateAMD64(data []byte) error {
	file, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("release binary is not a valid Linux ELF executable: %w", err)
	}
	defer file.Close()
	if file.Machine != elf.EM_X86_64 || file.Class != elf.ELFCLASS64 {
		return fmt.Errorf("release binary architecture is %s; expected x86-64", file.Machine)
	}
	return nil
}

func atomicReplace(path string, data []byte, continueUpdate func(string) error) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect installed RevKit binary: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("installed RevKit path is not a regular file")
	}
	parent := filepath.Dir(path)
	backupFile, err := os.CreateTemp(parent, ".revkit-backup-*.tmp")
	if err != nil {
		return err
	}
	backup := backupFile.Name()
	if err := backupFile.Close(); err != nil {
		os.Remove(backup)
		return err
	}
	if err := os.Remove(backup); err != nil {
		return err
	}
	if err := os.Link(path, backup); err != nil {
		return fmt.Errorf("preserve previous RevKit binary: %w", err)
	}
	keepBackup := true
	defer func() {
		if keepBackup {
			_ = os.Remove(backup)
		}
	}()
	tmp, err := os.CreateTemp(parent, ".revkit-update-*.tmp")
	if err != nil {
		return err
	}
	staged := tmp.Name()
	defer os.Remove(staged)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(info.Mode().Perm() | 0111); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(staged, path); err != nil {
		return fmt.Errorf("replace RevKit binary: %w", err)
	}
	if err := syncDirectory(parent); err != nil {
		if restoreErr := os.Rename(backup, path); restoreErr == nil {
			keepBackup = false
		} else {
			keepBackup = false
			return fmt.Errorf("sync RevKit installation directory: %v; previous binary remains at %s: %w", err, backup, restoreErr)
		}
		return fmt.Errorf("sync RevKit installation directory: %w", err)
	}
	if continueUpdate != nil {
		if err := continueUpdate(path); err != nil {
			if restoreErr := os.Rename(backup, path); restoreErr != nil {
				keepBackup = false
				return fmt.Errorf("new RevKit could not continue the update (%v), and previous binary could not be restored: %w", err, restoreErr)
			}
			keepBackup = false
			_ = syncDirectory(parent)
			return fmt.Errorf("new RevKit could not continue the update; previous binary restored: %w", err)
		}
	}
	if err := os.Remove(backup); err != nil {
		return fmt.Errorf("remove previous RevKit binary backup: %w", err)
	}
	keepBackup = false
	return syncDirectory(parent)
}

func trustedDownloadURL(u *url.URL) bool {
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

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
