package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sampleReport() Report {
	return Report{
		SchemaVersion:  1,
		Metadata:       Metadata{ID: "20261022-sample-a1b2c3", Name: "sample.exe", Path: "/tmp/sample.exe", Size: 12, SHA256: strings.Repeat("a", 64), Modified: time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)},
		Identification: Identification{Format: "PE", Class: "PE32", Architecture: "x86", Subsystem: "Windows console"},
		Summary:        "32-bit Windows console executable.",
		Explanation:    "This is a compiled Windows program targeting 32-bit x86.",
		Findings:       []Finding{{Title: "Readable strings", Meaning: "The file contains success and failure text.", Why: "Strings can help locate related code.", Evidence: []string{"Strings: success", "Strings: failure"}}},
		NextSteps:      []NextStep{{Action: "Find references to the failure string.", Tool: "Ghidra", Learn: []string{"PE executable basics", "Ghidra string references"}, Searches: []string{"Ghidra string xref beginner"}}},
		Evidence:       []Evidence{{Source: "PE headers", Output: "Subsystem: Windows console"}},
		Warnings:       []string{"Target was NOT executed."},
	}
}

func TestRenderersUseSharedReportDataAndEscapeHTML(t *testing.T) {
	report := sampleReport()
	report.Findings[0].Title = "Readable <strings>"
	markdown, err := RenderMarkdown(report)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(markdown, "Readable &lt;strings&gt;") || !strings.Contains(markdown, "What that means") || !strings.Contains(markdown, "Ghidra string xref beginner") || !strings.Contains(markdown, "Target was NOT executed.") {
		t.Fatalf("Markdown is missing report data:\n%s", markdown)
	}
	structured, err := RenderJSON(report)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Report
	if err := json.Unmarshal(structured, &decoded); err != nil || decoded.Findings[0].Title != report.Findings[0].Title {
		t.Fatalf("JSON report did not round-trip: %#v, %v", decoded, err)
	}
	page, err := RenderHTML(report)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(page, "<title>RevKit</title>") || !strings.Contains(page, "What that means") || !strings.Contains(page, "Readable &lt;strings&gt;") || strings.Contains(page, "Readable <strings>") {
		t.Fatalf("HTML title or escaping is incorrect:\n%s", page)
	}
}

func TestRenderersPreserveEvidenceBytes(t *testing.T) {
	value := sampleReport()
	value.Evidence = []Evidence{{Source: "strings", Output: "  Wrong password  \nflag{example}\n"}}
	jsonData, err := RenderJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Report
	if err := json.Unmarshal(jsonData, &decoded); err != nil {
		t.Fatal(err)
	}
	if got := decoded.Evidence[0].Output; got != value.Evidence[0].Output {
		t.Fatalf("JSON evidence changed: %q", got)
	}
	markdown, err := RenderMarkdown(value)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(markdown, "```text\n"+value.Evidence[0].Output+"```") {
		t.Fatalf("Markdown evidence changed: %q", markdown)
	}
	page, err := RenderHTML(value)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(page, "<pre>"+value.Evidence[0].Output+"</pre>") {
		t.Fatalf("HTML evidence changed: %q", page)
	}
}

func TestMarkdownFlattensUntrustedFilenames(t *testing.T) {
	value := sampleReport()
	value.Metadata.Name = "sample]\n## injected"
	markdown, err := RenderMarkdown(value)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(markdown, "\n## injected") {
		t.Fatalf("untrusted filename changed Markdown structure: %s", markdown)
	}
}

func TestSaveWritesMarkdownJSONHTMLAtomically(t *testing.T) {
	dir := t.TempDir()
	paths, err := Save(dir, sampleReport())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{paths.Markdown, paths.JSON, paths.HTML} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("report file missing: %s: %v", path, err)
		}
	}
	if filepath.Dir(paths.Markdown) != dir || filepath.Ext(paths.HTML) != ".html" {
		t.Fatalf("unexpected report paths: %#v", paths)
	}
	if _, err := Save(dir, sampleReport()); err != nil {
		t.Fatal(err)
	}
}

func TestLoadIndexSortsReportsAndSkipsUnrelatedFiles(t *testing.T) {
	dir := t.TempDir()
	older := sampleReport()
	older.Metadata.ID = "older"
	older.Metadata.Name = "older.elf"
	older.Metadata.Modified = older.Metadata.Modified.Add(-time.Hour)
	newer := sampleReport()
	newer.Metadata.ID = "newer"
	newer.Metadata.Name = "newer.exe"
	if _, err := Save(dir, older); err != nil {
		t.Fatal(err)
	}
	if _, err := Save(dir, newer); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.md"), []byte("not a report"), 0600); err != nil {
		t.Fatal(err)
	}
	entries, err := LoadIndex(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].ID != "newer" || entries[0].HTML != "newer.html" || entries[1].ID != "older" {
		t.Fatalf("report index = %#v", entries)
	}
}

func TestLoadIndexIncludesReportsWithLargeEvidence(t *testing.T) {
	dir := t.TempDir()
	value := sampleReport()
	value.Metadata.ID = "large-evidence"
	value.Evidence = []Evidence{{Source: "strings", Output: strings.Repeat("x", 5<<20)}}
	if _, err := Save(dir, value); err != nil {
		t.Fatal(err)
	}
	entries, err := LoadIndex(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].ID != "large-evidence" {
		t.Fatalf("large evidence report is missing from index: %#v", entries)
	}
}
