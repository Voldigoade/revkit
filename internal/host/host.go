package host

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

type Info struct {
	ID         string
	Arch       string
	PrettyName string
}

func Current() (Info, error) {
	return ReadOSRelease("/etc/os-release", runtime.GOARCH)
}

func ReadOSRelease(file, arch string) (Info, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return Info{}, fmt.Errorf("read OS release information: %w", err)
	}
	values := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		value = strings.Trim(value, `"'`)
		values[key] = value
	}
	info := Info{ID: strings.ToLower(values["ID"]), Arch: arch, PrettyName: values["PRETTY_NAME"]}
	if !Supported(info) {
		return info, fmt.Errorf("unsupported host: RevKit v0.1.0 supports Debian and Ubuntu x86-64 only")
	}
	return info, nil
}

func Supported(info Info) bool {
	if info.Arch != "amd64" {
		return false
	}
	return info.ID == "debian" || info.ID == "ubuntu"
}
