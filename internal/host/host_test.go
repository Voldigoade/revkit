package host

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadOSReleaseAllowsDebianUbuntuX8664(t *testing.T) {
	for _, id := range []string{"debian", "ubuntu"} {
		file := filepath.Join(t.TempDir(), "os-release")
		if err := os.WriteFile(file, []byte("ID="+id+"\nPRETTY_NAME=\"Test OS\"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		info, err := ReadOSRelease(file, "amd64")
		if err != nil || info.PrettyName != "Test OS" {
			t.Fatalf("ReadOSRelease(%s) = %#v, %v", id, info, err)
		}
	}
}

func TestReadOSReleaseRejectsUnsupportedArchitectureAndDistro(t *testing.T) {
	file := filepath.Join(t.TempDir(), "os-release")
	if err := os.WriteFile(file, []byte("ID=debian\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadOSRelease(file, "arm64"); err == nil {
		t.Fatal("ReadOSRelease accepted arm64")
	}
	if err := os.WriteFile(file, []byte("ID=fedora\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadOSRelease(file, "amd64"); err == nil {
		t.Fatal("ReadOSRelease accepted Fedora")
	}
}

func TestReadOSReleaseAcceptsDebianFamilyIDLike(t *testing.T) {
	file := filepath.Join(t.TempDir(), "os-release")
	if err := os.WriteFile(file, []byte("ID=linuxmint\nID_LIKE=ubuntu debian\nPRETTY_NAME=Mint\n"), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := ReadOSRelease(file, "amd64")
	if err != nil || !Supported(info) {
		t.Fatalf("ReadOSRelease derivative = %#v, %v", info, err)
	}
}

func TestReadOSReleaseDoesNotMatchIDLikeSubstrings(t *testing.T) {
	file := filepath.Join(t.TempDir(), "os-release")
	if err := os.WriteFile(file, []byte("ID=custom\nID_LIKE=notdebian\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadOSRelease(file, "amd64"); err == nil {
		t.Fatal("ReadOSRelease accepted an unrelated ID_LIKE value")
	}
}
