package state

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	ActionNone    = "none"
	ActionInstall = "install"
	ActionUpdate  = "update"
	ActionRepair  = "repair"
	CheckInterval = 7 * 24 * time.Hour
)

type State struct {
	Root        string               `json:"root"`
	Version     string               `json:"version"`
	Tools       map[string]ToolState `json:"tools"`
	APTUpdated  time.Time            `json:"apt_updated,omitempty"`
	LastChecked time.Time            `json:"last_checked,omitempty"`
}

type ToolState struct {
	Version   string    `json:"version,omitempty"`
	Digest    string    `json:"digest,omitempty"`
	Path      string    `json:"path,omitempty"`
	CheckedAt time.Time `json:"checked_at,omitempty"`
}

func ResolveRoot(requested, home string) (string, error) {
	if home == "" || strings.IndexByte(home, 0) >= 0 {
		return "", fmt.Errorf("home directory is not available")
	}
	if requested == "" {
		requested = filepath.Join(home, "Desktop", "RevKit")
	} else {
		if strings.IndexByte(requested, 0) >= 0 {
			return "", fmt.Errorf("installation path contains a NUL byte")
		}
		if requested == "~" {
			requested = home
		} else if strings.HasPrefix(requested, "~/") {
			requested = filepath.Join(home, filepath.FromSlash(strings.TrimPrefix(requested, "~/")))
		} else if strings.HasPrefix(requested, "~") {
			return "", fmt.Errorf("named-user installation paths are not supported")
		}
	}
	if !filepath.IsAbs(requested) {
		var err error
		requested, err = filepath.Abs(requested)
		if err != nil {
			return "", err
		}
	}
	return filepath.Abs(filepath.Clean(requested))
}

func Load(file string) (State, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		if os.IsNotExist(err) {
			return State{Tools: map[string]ToolState{}}, nil
		}
		return State{}, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return State{}, fmt.Errorf("read state file: %w", err)
	}
	if s.Tools == nil {
		s.Tools = map[string]ToolState{}
	}
	return s, nil
}

func Save(file string, state State) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(file), 0755); err != nil {
		return err
	}
	if current, err := os.ReadFile(file); err == nil && bytes.Equal(current, data) {
		return nil
	}
	tmp, err := os.CreateTemp(filepath.Dir(file), ".state-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, 0644); err != nil {
		return err
	}
	return os.Rename(name, file)
}

func CompareVersions(a, b string) int {
	a = strings.TrimPrefix(strings.TrimSpace(a), "v")
	b = strings.TrimPrefix(strings.TrimSpace(b), "v")
	a, _, _ = strings.Cut(a, "+")
	b, _, _ = strings.Cut(b, "+")
	coreA, preA, hasPreA := strings.Cut(a, "-")
	coreB, preB, hasPreB := strings.Cut(b, "-")
	if cmp := compareVersionParts(versionParts(coreA), versionParts(coreB), true); cmp != 0 {
		return cmp
	}
	if !hasPreA && hasPreB {
		return 1
	}
	if hasPreA && !hasPreB {
		return -1
	}
	if !hasPreA {
		return 0
	}
	return comparePrerelease(strings.Split(preA, "."), strings.Split(preB, "."))
}

var versionPartPattern = regexp.MustCompile(`[0-9]+|[A-Za-z]+`)

func versionParts(v string) []string {
	return versionPartPattern.FindAllString(strings.TrimSpace(strings.TrimPrefix(strings.ToLower(v), "v")), -1)
}

func compareVersionParts(a, b []string, padZero bool) int {
	limit := len(a)
	if len(b) > limit {
		limit = len(b)
	}
	for i := 0; i < limit; i++ {
		left, right := "0", "0"
		if i < len(a) {
			left = a[i]
		}
		if i < len(b) {
			right = b[i]
		}
		if padZero && (left == "" || right == "") {
			continue
		}
		li, le := strconv.ParseUint(left, 10, 64)
		ri, re := strconv.ParseUint(right, 10, 64)
		switch {
		case le == nil && re == nil && li < ri:
			return -1
		case le == nil && re == nil && li > ri:
			return 1
		case le == nil && re != nil:
			return -1
		case le != nil && re == nil:
			return 1
		case le != nil && re != nil:
			if cmp := strings.Compare(left, right); cmp != 0 {
				return cmp
			}
		}
	}
	return 0
}

func comparePrerelease(a, b []string) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		if i == len(a) {
			return -1
		}
		if i == len(b) {
			return 1
		}
		left, right := a[i], b[i]
		li, le := strconv.ParseUint(left, 10, 64)
		ri, re := strconv.ParseUint(right, 10, 64)
		switch {
		case le == nil && re == nil && li < ri:
			return -1
		case le == nil && re == nil && li > ri:
			return 1
		case le == nil && re != nil:
			return -1
		case le != nil && re == nil:
			return 1
		case le != nil && re != nil:
			if cmp := strings.Compare(strings.ToLower(left), strings.ToLower(right)); cmp != 0 {
				return cmp
			}
		}
	}
	return 0
}

func Decide(installed, broken bool, current, latest string) string {
	if !installed {
		return ActionInstall
	}
	if broken {
		return ActionRepair
	}
	if latest != "" && current != "" && CompareVersions(current, latest) < 0 {
		return ActionUpdate
	}
	return ActionNone
}

func NeedsCheck(now, checkedAt time.Time) bool {
	return checkedAt.IsZero() || now.Sub(checkedAt) >= CheckInterval
}
