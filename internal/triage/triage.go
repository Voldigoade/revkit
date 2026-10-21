package triage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"html"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const maxCommandOutput = 2 << 20

type RunFunc func(name string, args ...string) ([]byte, error)

type Analyzer struct {
	Run RunFunc
}

type Result struct {
	Markdown string
	Hash     string
}

func (a Analyzer) Analyze(file string) (Result, error) {
	absolute, err := filepath.Abs(file)
	if err != nil {
		return Result{}, err
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return Result{}, fmt.Errorf("stat target: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Result{}, fmt.Errorf("target must be a regular file")
	}
	f, err := os.Open(absolute)
	if err != nil {
		return Result{}, err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		f.Close()
		return Result{}, err
	}
	if err := f.Close(); err != nil {
		return Result{}, err
	}
	digest := fmt.Sprintf("%x", h.Sum(nil))
	var out strings.Builder
	fmt.Fprintln(&out, "# RevKit static triage")
	fmt.Fprintln(&out)
	fmt.Fprintln(&out, "> Target was NOT executed.")
	fmt.Fprintln(&out)
	fmt.Fprintf(&out, "- File: <code>%s</code>\n- Size: %d bytes\n- Mode: `%s`\n- Modified: %s\n- SHA-256: `%s`\n", html.EscapeString(absolute), info.Size(), info.Mode().Perm(), info.ModTime().Format(time.RFC3339), digest)
	for _, step := range []struct {
		title string
		name  string
		args  []string
	}{
		{title: "file", name: "file", args: []string{absolute}},
		{title: "checksec", name: "checksec", args: []string{"--file=" + absolute}},
		{title: "ELF header, sections, segments, and symbols", name: "readelf", args: []string{"-h", "-S", "-l", "-s", absolute}},
		{title: "Printable strings", name: "strings", args: []string{"-a", "-n", "4", absolute}},
	} {
		data, err := a.run(step.name, step.args...)
		if err != nil && len(data) == 0 {
			fmt.Fprintf(&out, "\n## %s\n\n_Not available: %s_\n", step.title, html.EscapeString(err.Error()))
			continue
		}
		fence := codeFence(string(data))
		fmt.Fprintf(&out, "\n## %s\n\n%stext\n%s\n%s\n", step.title, fence, strings.TrimSpace(string(data)), fence)
	}
	return Result{Markdown: out.String(), Hash: digest}, nil
}

func (a Analyzer) run(name string, args ...string) ([]byte, error) {
	if a.Run != nil {
		return a.Run(name, args...)
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	var buf limitedBuffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err = cmd.Run()
	data := buf.Bytes()
	if buf.limited {
		data = append(append([]byte(nil), data...), []byte("\n[output truncated after 2 MiB]\n")...)
	}
	return data, err
}

func codeFence(text string) string {
	longest, current := 0, 0
	for _, r := range text {
		if r == '`' {
			current++
			if current > longest {
				longest = current
			}
		} else {
			current = 0
		}
	}
	if longest < 2 {
		longest = 2
	}
	return strings.Repeat("`", longest+1)
}

type limitedBuffer struct {
	bytes.Buffer
	limited bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	original := len(p)
	remaining := maxCommandOutput - b.Len()
	if remaining <= 0 {
		b.limited = true
		return original, nil
	}
	if len(p) > remaining {
		p = p[:remaining]
		b.limited = true
	}
	_, err := b.Buffer.Write(p)
	return original, err
}

func SaveReport(dir, originalPath, content string) (string, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	base := filepath.Base(originalPath)
	base = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, base)
	stamp := time.Now().Format("20060102-150405")
	for i := 0; i < 100; i++ {
		suffix := ""
		if i > 0 {
			suffix = fmt.Sprintf("-%d", i)
		}
		path := filepath.Join(dir, fmt.Sprintf("triage-%s-%s%s.md", stamp, base, suffix))
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if os.IsExist(err) {
			continue
		}
		if err != nil {
			return "", err
		}
		if _, err := io.WriteString(f, content); err != nil {
			f.Close()
			os.Remove(path)
			return "", err
		}
		if err := f.Close(); err != nil {
			return "", err
		}
		return path, nil
	}
	return "", fmt.Errorf("could not choose a unique report name")
}
