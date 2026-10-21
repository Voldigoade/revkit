package triage

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnalyzeIsStaticAndProducesHashAndFileMetadata(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "sample.bin")
	if err := os.WriteFile(target, []byte("hello static analysis\n"), 0600); err != nil {
		t.Fatal(err)
	}
	called := []string{}
	analyzer := Analyzer{Run: func(name string, args ...string) ([]byte, error) {
		called = append(called, name)
		return []byte("file output\n"), nil
	}}
	result, err := analyzer.Analyze(target)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Markdown, "Target was NOT executed.") || !strings.Contains(result.Markdown, "SHA-256") || !strings.Contains(result.Markdown, "file output") {
		t.Fatalf("report missing expected static evidence:\n%s", result.Markdown)
	}
	for _, name := range called {
		if name == target {
			t.Fatalf("analyzer attempted to execute target %q", target)
		}
	}
}

func TestAnalyzeRejectsDirectories(t *testing.T) {
	if _, err := (Analyzer{}).Analyze(t.TempDir()); err == nil {
		t.Fatal("Analyze accepted a directory")
	}
}

func TestLimitedBufferCapsOutputAndRecordsTruncation(t *testing.T) {
	var output limitedBuffer
	input := bytes.Repeat([]byte("x"), maxCommandOutput+1)
	if n, err := output.Write(input); err != nil || n != len(input) {
		t.Fatalf("Write() = %d, %v", n, err)
	}
	if output.Len() != maxCommandOutput || !output.limited {
		t.Fatalf("buffer length=%d limited=%v", output.Len(), output.limited)
	}
}

func TestCodeFenceCannotBeClosedByToolOutput(t *testing.T) {
	if got := codeFence("result ``` with `` more"); got != "````" {
		t.Fatalf("codeFence() = %q, want four backticks", got)
	}
}
