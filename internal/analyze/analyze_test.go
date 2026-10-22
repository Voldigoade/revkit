package analyze

import (
	"archive/zip"
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Voldigoade/revkit/internal/report"
	"github.com/Voldigoade/revkit/internal/state"
)

type recordingRunner struct {
	commands []string
	args     [][]string
	versions map[string]string
	outputs  map[string][]byte
}

func (r *recordingRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.commands = append(r.commands, name)
	r.args = append(r.args, append([]string(nil), args...))
	if len(args) == 1 && args[0] == "--version" {
		version := r.versions[name]
		if version == "" {
			version = r.versions[filepath.Base(name)]
		}
		if version != "" {
			return []byte(version), nil
		}
	}
	if output := r.outputs[filepath.Base(name)]; output != nil {
		return append([]byte(nil), output...), nil
	}
	return []byte(name + " evidence"), nil
}

func TestAnalyzePrefersVerifiedRevKitManagedAnalyzer(t *testing.T) {
	root := t.TempDir()
	toolDir := filepath.Join(root, "tools", "cli", "capa")
	if err := os.MkdirAll(toolDir, 0755); err != nil {
		t.Fatal(err)
	}
	managed := filepath.Join(toolDir, "capa")
	if err := os.WriteFile(managed, []byte("managed analyzer"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := state.Save(filepath.Join(root, "state.json"), state.State{Tools: map[string]state.ToolState{"capa": {Path: filepath.Join("tools", "cli", "capa", "capa")}}}); err != nil {
		t.Fatal(err)
	}
	runner := &recordingRunner{versions: map[string]string{"capa": "capa 10.0.0"}}
	lookPath := func(name string) (string, error) {
		if name == "capa" {
			return "/usr/bin/capa", nil
		}
		return "", exec.ErrNotFound
	}
	if _, err := (Analyzer{Root: root, Runner: runner, LookPath: lookPath}).Analyze(context.Background(), writeInput(t, minimalPE(false))); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) < 2 || runner.commands[0] != managed || runner.commands[1] != managed {
		t.Fatalf("analysis did not use the verified managed analyzer: %v", runner.commands)
	}
}

func TestAnalyzeRejectsManagedAnalyzerDirectorySymlink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "capa"), []byte("external analyzer"), 0755); err != nil {
		t.Fatal(err)
	}
	toolParent := filepath.Join(root, "tools", "cli")
	if err := os.MkdirAll(toolParent, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(toolParent, "capa")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	if err := state.Save(filepath.Join(root, "state.json"), state.State{Tools: map[string]state.ToolState{"capa": {Path: filepath.Join("tools", "cli", "capa", "capa")}}}); err != nil {
		t.Fatal(err)
	}
	runner := &recordingRunner{versions: map[string]string{"capa": "capa 10.0.0"}}
	lookPath := func(name string) (string, error) {
		if name == "capa" {
			return "/usr/bin/capa", nil
		}
		return "", exec.ErrNotFound
	}
	got, err := (Analyzer{Root: root, Runner: runner, LookPath: lookPath}).Analyze(context.Background(), writeInput(t, minimalPE(false)))
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 0 || len(got.Warnings) != 1 || !strings.Contains(got.Warnings[0], "capa") {
		t.Fatalf("analysis used a symlinked managed analyzer: commands=%v warnings=%v", runner.commands, got.Warnings)
	}
}

func TestAnalyzeELFAndPEUseFormatSpecificTools(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		format      string
		arch        string
		class       string
		wantReadELF bool
	}{
		{name: "ELF", data: minimalELF(), format: "ELF", arch: "x86-64", class: "ELF64", wantReadELF: true},
		{name: "PE", data: minimalPE(false), format: "PE", arch: "x86", class: "PE32", wantReadELF: false},
		{name: "PE32+", data: minimalPE(true), format: "PE", arch: "x86-64", class: "PE32+", wantReadELF: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writeInput(t, tc.data)
			runner := &recordingRunner{}
			lookPath := func(name string) (string, error) {
				if name == "readelf" || name == "checksec" {
					return name, nil
				}
				return "", exec.ErrNotFound
			}
			got, err := (Analyzer{Runner: runner, LookPath: lookPath}).Analyze(context.Background(), path)
			if err != nil {
				t.Fatal(err)
			}
			if got.Identification.Format != tc.format || got.Identification.Architecture != tc.arch || got.Identification.Class != tc.class {
				t.Fatalf("identification = %#v", got.Identification)
			}
			hasReadELF := contains(runner.commands, "readelf") || contains(runner.commands, "checksec")
			if hasReadELF != tc.wantReadELF {
				t.Fatalf("ELF tools called=%v; commands=%v", hasReadELF, runner.commands)
			}
			if got.Metadata.SHA256 == "" || got.Summary == "" || got.Explanation == "" || len(got.NextSteps) == 0 {
				t.Fatalf("report is missing beginner guidance: %#v", got)
			}
			if tc.format == "PE" && !strings.Contains(got.Explanation, "standard Windows executable format") {
				t.Fatalf("PE report does not explain the format: %q", got.Explanation)
			}
			if tc.format == "PE" && strings.Contains(got.Explanation, "instruction set instruction set") {
				t.Fatalf("PE explanation repeats terminology: %q", got.Explanation)
			}
		})
	}
}

func TestAnalyzeRecognizesZIPTextAndUnknownBinary(t *testing.T) {
	zipPath := filepath.Join(t.TempDir(), "archive.zip")
	zf, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(zf)
	if _, err := zw.Create("readme.txt"); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zf.Close(); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		path string
		data []byte
		want string
	}{
		{name: "ZIP", path: zipPath, want: "ZIP archive"},
		{name: "text", data: []byte("#!/bin/sh\nprintf safe\n"), want: "text/script"},
		{name: "unknown", data: []byte{0, 1, 2, 3, 0xfe, 0xff}, want: "unknown binary"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := tc.path
			if path == "" {
				path = writeInput(t, tc.data)
			}
			got, err := (Analyzer{}).Analyze(context.Background(), path)
			if err != nil {
				t.Fatal(err)
			}
			if got.Identification.Format != tc.want {
				t.Fatalf("format = %q, want %q", got.Identification.Format, tc.want)
			}
		})
	}
}

func TestAnalyzePreservesCompleteTextFileContents(t *testing.T) {
	contents := "#!/bin/sh\nprintf 'Wrong password'\nsecret token flag{example}\n"
	path := writeInput(t, []byte(contents))
	value, err := (Analyzer{}).Analyze(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if got := evidenceOutput(value.Evidence, "Text content"); got != contents {
		t.Fatalf("text content evidence = %q, want original file %q", got, contents)
	}
}

func TestLongPrintableStringsRemainEvidenceWithoutBecomingSummaryClues(t *testing.T) {
	longString := "runtime-error: " + strings.Repeat("allocator-state ", 80) + "Wrong passwordUsage: %s passGratz man :)"
	var value report.Report
	addStringEvidence([]string{longString}, &value)
	if got := evidenceOutput(value.Evidence, "Printable strings"); got != longString {
		t.Fatalf("printable-string evidence changed: got %q", got)
	}
	if len(value.Findings) != 1 {
		t.Fatalf("expected concise message clues from the long string, got %#v", value.Findings)
	}
	for _, clue := range []string{"Wrong password", "Usage: %s pass", "Gratz man :)"} {
		if !contains(value.Findings[0].Evidence, clue) {
			t.Errorf("long string summary is missing clue %q: %#v", clue, value.Findings[0].Evidence)
		}
	}
}

func TestSpecificMessageCluesTakePriorityOverGenericRuntimeText(t *testing.T) {
	got := importantStrings([]string{"Failed", "Wrong password", "Success"})
	if len(got) != 1 || got[0] != "Wrong password" {
		t.Fatalf("summary clues = %#v, want only the specific target message", got)
	}
}

func TestTextDetectionAcceptsUnicodeAndRejectsControls(t *testing.T) {
	if !isText([]byte("#!/bin/sh\necho café\n")) {
		t.Fatal("valid UTF-8 text with a non-ASCII character was rejected")
	}
	if isText([]byte("readable\x00binary")) {
		t.Fatal("text containing a NUL byte was accepted")
	}
}

func TestAnalysisPreservesTargetStringsAndAnalyzerOutputAcrossReports(t *testing.T) {
	stringsFound := []string{"Wrong password", "Gratz man :) ", "Usage: %s pass", "flag{example}", "secret", "token"}
	for index := range 65 {
		stringsFound = append(stringsFound, fmt.Sprintf("ordinary-string-%02d", index))
	}
	stringsFound = append(stringsFound, "late-evidence-after-sixty", strings.Repeat("x", 300)+"tail-marker")
	path := writeInput(t, append(minimalPE(false), []byte("\x00"+strings.Join(stringsFound, "\x00")+"\x00")...))
	flossOutput := "Wrong password\nGratz man :)\nflag{example}\nsecret\ntoken\n"
	capaOutput := "possible capability: token lookup\npassword comparison\n"
	runner := &recordingRunner{
		versions: map[string]string{"capa": "capa 10.0.0", "floss": "FLOSS version 3.2.0"},
		outputs:  map[string][]byte{"capa": []byte(capaOutput), "floss": []byte(flossOutput)},
	}
	lookPath := func(name string) (string, error) {
		if name == "capa" || name == "floss" {
			return name, nil
		}
		return "", exec.ErrNotFound
	}
	value, err := (Analyzer{Runner: runner, LookPath: lookPath}).Analyze(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	printable := evidenceOutput(value.Evidence, "Printable strings")
	for _, item := range []string{"Wrong password", "Gratz man :) ", "Usage: %s pass", "flag{example}", "secret", "token", "late-evidence-after-sixty", "tail-marker"} {
		if !strings.Contains(printable, item) {
			t.Errorf("printable-string evidence lost %q", item)
		}
	}
	var messageFinding []string
	for _, finding := range value.Findings {
		if finding.Title == "Program messages and usage" {
			messageFinding = finding.Evidence
		}
	}
	if !contains(messageFinding, "Wrong password") || !strings.Contains(value.NextSteps[0].Action, `Search for "Wrong password"`) {
		t.Fatalf("beginner guidance did not prioritize the target's own message: findings=%#v next steps=%#v", value.Findings, value.NextSteps)
	}
	if got := evidenceOutput(value.Evidence, "capa"); got != capaOutput {
		t.Errorf("capa evidence = %q, want original output %q", got, capaOutput)
	}
	if got := evidenceOutput(value.Evidence, "floss"); got != flossOutput {
		t.Errorf("FLOSS evidence = %q, want original output %q", got, flossOutput)
	}

	jsonData, err := report.RenderJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	markdown, err := report.RenderMarkdown(value)
	if err != nil {
		t.Fatal(err)
	}
	html, err := report.RenderHTML(value)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []string{"Wrong password", "flag{example}", "secret", "token", "late-evidence-after-sixty", "tail-marker", "password comparison"} {
		for _, rendered := range []struct {
			name string
			data string
		}{{"JSON", string(jsonData)}, {"Markdown", markdown}, {"HTML", html}} {
			if !strings.Contains(rendered.data, item) {
				t.Errorf("%s report lost evidence %q", rendered.name, item)
			}
		}
	}
}

func TestAnalyzerOutputLimitIsExplicitAndPreservesPrefix(t *testing.T) {
	path := writeInput(t, minimalPE(false))
	output := bytes.Repeat([]byte("x"), maxEvidenceOutput+32)
	runner := &recordingRunner{
		versions: map[string]string{"capa": "capa 10.0.0"},
		outputs:  map[string][]byte{"capa": output},
	}
	lookPath := func(name string) (string, error) {
		if name == "capa" {
			return name, nil
		}
		return "", exec.ErrNotFound
	}
	value, err := (Analyzer{Runner: runner, LookPath: lookPath}).Analyze(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if got := evidenceOutput(value.Evidence, "capa"); len(got) != maxEvidenceOutput {
		t.Fatalf("preserved analyzer output length = %d, want %d", len(got), maxEvidenceOutput)
	}
	if !containsWarning(value.Warnings, "output exceeded") || !containsWarning(value.Warnings, "first 131072 bytes") {
		t.Fatalf("truncated analyzer output was not clearly reported: %v", value.Warnings)
	}
}

func evidenceOutput(evidence []report.Evidence, source string) string {
	for _, item := range evidence {
		if item.Source == source {
			return item.Output
		}
	}
	return ""
}

func containsWarning(warnings []string, part string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, part) {
			return true
		}
	}
	return false
}

func TestAnalyzeNeverExecutesTarget(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	path := writeInput(t, []byte("#!/bin/sh\nprintf ran > '"+marker+"'\n"))
	if _, err := (Analyzer{}).Analyze(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("target was executed; marker stat error = %v", err)
	}
}

func TestAnalyzeRunsOnlySupportedSafeVersionsOfOptionalAnalyzers(t *testing.T) {
	path := writeInput(t, minimalPE(false))
	lookPath := func(name string) (string, error) {
		if name == "capa" || name == "floss" {
			return name, nil
		}
		return "", exec.ErrNotFound
	}
	runner := &recordingRunner{versions: map[string]string{"capa": "capa 10.0.0", "floss": "FLOSS version 3.2.0"}}
	got, err := (Analyzer{Runner: runner, LookPath: lookPath}).Analyze(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"capa", "floss"} {
		foundVersionCheck, foundInput := false, false
		for index, command := range runner.commands {
			if command != name {
				continue
			}
			foundVersionCheck = foundVersionCheck || len(runner.args[index]) == 1 && runner.args[index][0] == "--version"
			foundInput = foundInput || len(runner.args[index]) > 0 && runner.args[index][len(runner.args[index])-1] == path
		}
		if !foundVersionCheck || !foundInput || !containsEvidence(got.Evidence, name) {
			t.Fatalf("%s calls did not verify the safe version and analyze the input: calls=%#v report=%#v", name, runner.args, got)
		}
	}

	runner = &recordingRunner{versions: map[string]string{"capa": "capa 9.4.0", "floss": "FLOSS version 3.1.1"}}
	got, err = (Analyzer{Runner: runner, LookPath: lookPath}).Analyze(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	for index, args := range runner.args {
		if len(args) > 0 && args[len(args)-1] == path {
			t.Fatalf("outdated %s received the untrusted input", runner.commands[index])
		}
	}
	if len(got.Warnings) != 2 || containsEvidence(got.Evidence, "capa") || containsEvidence(got.Evidence, "floss") {
		t.Fatalf("outdated analyzer versions were not skipped with warnings: %#v", got)
	}
}

func containsEvidence(evidence []report.Evidence, source string) bool {
	for _, item := range evidence {
		if item.Source == source {
			return true
		}
	}
	return false
}

func TestAnalyzeRejectsOversizedInput(t *testing.T) {
	path := writeInput(t, []byte("12345"))
	_, err := (Analyzer{MaxFileSize: 4}).Analyze(context.Background(), path)
	if err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("Analyze error = %v, want size limit", err)
	}
}

func TestCommandRunnerBoundsTimeAndOutput(t *testing.T) {
	if os.Getenv("REVKIT_RUNNER_HELPER") == "1" {
		if os.Getenv("REVKIT_RUNNER_MODE") == "sleep" {
			time.Sleep(2 * time.Second)
		} else if os.Getenv("REVKIT_RUNNER_MODE") == "env" {
			_, _ = os.Stdout.Write([]byte(os.Getenv("CAPA_LOAD_VIV_WORKSPACE") + ":" + os.Getenv("FLOSS_LOAD_VIV_WORKSPACE")))
		} else {
			_, _ = os.Stdout.Write([]byte(strings.Repeat("x", 8192)))
		}
		os.Exit(0)
	}

	timeoutRunner := CommandRunner{Timeout: 500 * time.Millisecond, MaxOutput: 64}
	runner := CommandRunner{Timeout: 5 * time.Second, MaxOutput: 64}
	t.Setenv("REVKIT_RUNNER_HELPER", "1")
	t.Setenv("REVKIT_RUNNER_MODE", "sleep")
	start := time.Now()
	_, err := timeoutRunner.Run(context.Background(), os.Args[0], "-test.run=TestCommandRunnerBoundsTimeAndOutput")
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("command did not time out promptly: elapsed=%s err=%v", time.Since(start), err)
	}

	t.Setenv("REVKIT_RUNNER_MODE", "output")
	got, err := runner.Run(context.Background(), os.Args[0], "-test.run=TestCommandRunnerBoundsTimeAndOutput")
	if err == nil || !strings.Contains(err.Error(), "output limit") || len(got) > 64 {
		t.Fatalf("output cap result length=%d err=%v", len(got), err)
	}

	t.Setenv("CAPA_LOAD_VIV_WORKSPACE", "1")
	t.Setenv("FLOSS_LOAD_VIV_WORKSPACE", "1")
	t.Setenv("REVKIT_RUNNER_MODE", "env")
	got, err = runner.Run(context.Background(), os.Args[0], "-test.run=TestCommandRunnerBoundsTimeAndOutput")
	if err != nil || string(got) != "0:0" {
		t.Fatalf("dangerous workspace loading was not disabled: output=%q err=%v", got, err)
	}
}

func minimalELF() []byte {
	data := make([]byte, 64)
	copy(data, []byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)})
	binary.LittleEndian.PutUint16(data[16:], uint16(elf.ET_DYN))
	binary.LittleEndian.PutUint16(data[18:], uint16(elf.EM_X86_64))
	binary.LittleEndian.PutUint32(data[20:], uint32(elf.EV_CURRENT))
	binary.LittleEndian.PutUint16(data[52:], 64)
	binary.LittleEndian.PutUint16(data[58:], 64)
	return data
}

func minimalPE(plus bool) []byte {
	const peOffset = 0x80
	optionalSize := 224
	machine, magic := uint16(0x14c), uint16(0x10b)
	if plus {
		optionalSize, machine, magic = 240, 0x8664, 0x20b
	}
	data := make([]byte, peOffset+4+20+optionalSize+40)
	copy(data, "MZ")
	binary.LittleEndian.PutUint32(data[0x3c:], peOffset)
	copy(data[peOffset:], "PE\x00\x00")
	coff := data[peOffset+4:]
	binary.LittleEndian.PutUint16(coff[0:], machine)
	binary.LittleEndian.PutUint16(coff[2:], 1)
	binary.LittleEndian.PutUint16(coff[16:], uint16(optionalSize))
	binary.LittleEndian.PutUint16(coff[18:], 0x0102)
	optional := coff[20:]
	binary.LittleEndian.PutUint16(optional[0:], magic)
	if plus {
		binary.LittleEndian.PutUint16(optional[68:], 3)
		binary.LittleEndian.PutUint32(optional[108:], 16)
	} else {
		binary.LittleEndian.PutUint16(optional[68:], 3)
		binary.LittleEndian.PutUint32(optional[92:], 16)
	}
	section := optional[optionalSize:]
	copy(section, ".text")
	binary.LittleEndian.PutUint32(section[8:], 1)
	return data
}

func writeInput(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input.bin")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}
