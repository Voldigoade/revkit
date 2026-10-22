package selfupdate

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestUpdateDecisionUsesStableNewerReleases(t *testing.T) {
	for _, test := range []struct {
		current string
		latest  string
		want    bool
	}{
		{"v0.1.0", "v0.2.0", true},
		{"v0.2.0", "v0.2.0", false},
		{"v0.3.0", "v0.2.0", false},
		{"dev", "v0.2.0", false},
		{"v0.1.0-rc.1", "v0.2.0-rc.1", false},
	} {
		if got := ShouldUpdate(test.current, test.latest); got != test.want {
			t.Errorf("ShouldUpdate(%q, %q) = %v, want %v", test.current, test.latest, got, test.want)
		}
	}
}

func TestChecksumMismatchIsRejected(t *testing.T) {
	if _, err := VerifyChecksum([]byte("release"), "0000000000000000000000000000000000000000000000000000000000000000  revkit-linux-amd64\n", "revkit-linux-amd64"); err == nil {
		t.Fatal("VerifyChecksum accepted a mismatched digest")
	}
	if _, err := VerifyChecksum([]byte("release"), strings.Repeat("a", 64)+"  another-file\n", "revkit-linux-amd64"); err == nil {
		t.Fatal("VerifyChecksum accepted a checksum for a different asset")
	}
}

func TestAtomicReplaceRestoresPreviousBinaryWhenRelaunchFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revkit")
	previous := []byte("previous binary")
	if err := os.WriteFile(path, previous, 0755); err != nil {
		t.Fatal(err)
	}
	err := atomicReplace(path, []byte("new binary"), func(string) error { return os.ErrPermission })
	if err == nil {
		t.Fatal("atomicReplace succeeded after the new version failed to start")
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil || string(got) != string(previous) {
		t.Fatalf("previous binary was not restored: bytes=%q err=%v", got, readErr)
	}
	info, statErr := os.Stat(path)
	if statErr != nil || info.Mode().Perm()&0111 == 0 {
		t.Fatalf("restored binary is not executable: info=%v err=%v", info, statErr)
	}
}

func TestUpdateChecksumRejectionKeepsInstalledExecutable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revkit")
	previous := []byte("previous binary")
	if err := os.WriteFile(path, previous, 0755); err != nil {
		t.Fatal(err)
	}
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var body string
		switch request.URL.Path {
		case "/repos/Voldigoade/revkit/releases/latest":
			body = `{"tag_name":"v0.2.0","assets":[{"name":"revkit-linux-amd64","browser_download_url":"https://github.com/Voldigoade/revkit/releases/download/v0.2.0/revkit-linux-amd64"},{"name":"SHA256SUMS","browser_download_url":"https://github.com/Voldigoade/revkit/releases/download/v0.2.0/SHA256SUMS"}]}`
		case "/Voldigoade/revkit/releases/download/v0.2.0/SHA256SUMS":
			body = strings.Repeat("0", 64) + "  revkit-linux-amd64\n"
		case "/Voldigoade/revkit/releases/download/v0.2.0/revkit-linux-amd64":
			body = "unverified executable"
		default:
			t.Fatalf("unexpected release request: %s", request.URL)
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
	})
	continued := false
	_, err := (Updater{Client: &http.Client{Transport: transport}}).Update(context.Background(), "v0.1.0", path, func(string) error {
		continued = true
		return nil
	})
	if err == nil || continued {
		t.Fatalf("invalid checksum reached replacement: err=%v continued=%v", err, continued)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(previous) {
		t.Fatalf("checksum failure changed the installed executable: %q, %v", got, err)
	}
}
