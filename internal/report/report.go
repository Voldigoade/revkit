package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const maxReportSize = 4 << 20

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,95}$`)

type Report struct {
	SchemaVersion  int            `json:"schema_version"`
	TargetExecuted bool           `json:"target_executed"`
	Metadata       Metadata       `json:"metadata"`
	Identification Identification `json:"identification"`
	Summary        string         `json:"summary"`
	Explanation    string         `json:"what_it_means"`
	Findings       []Finding      `json:"findings"`
	NextSteps      []NextStep     `json:"next_steps"`
	Evidence       []Evidence     `json:"evidence"`
	Warnings       []string       `json:"warnings"`
}

type Metadata struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Path      string    `json:"path"`
	Size      int64     `json:"size"`
	SHA256    string    `json:"sha256"`
	Modified  time.Time `json:"modified"`
	CreatedAt time.Time `json:"created_at"`
}

type Identification struct {
	Format       string `json:"format"`
	Class        string `json:"class,omitempty"`
	Architecture string `json:"architecture"`
	Endianness   string `json:"endianness,omitempty"`
	Subsystem    string `json:"subsystem,omitempty"`
}

type Finding struct {
	Title    string   `json:"title"`
	Meaning  string   `json:"meaning"`
	Why      string   `json:"why_it_matters"`
	Evidence []string `json:"evidence"`
}

type NextStep struct {
	Action   string   `json:"action"`
	Tool     string   `json:"tool,omitempty"`
	Learn    []string `json:"learn_first"`
	Searches []string `json:"search_queries"`
}

type Evidence struct {
	Source string `json:"source"`
	Output string `json:"output"`
}

type Paths struct {
	Markdown string
	JSON     string
	HTML     string
}

type IndexEntry struct {
	ID           string    `json:"id"`
	Filename     string    `json:"filename"`
	HTML         string    `json:"html"`
	Format       string    `json:"format"`
	Architecture string    `json:"architecture"`
	Size         int64     `json:"size"`
	CreatedAt    time.Time `json:"created_at"`
	Summary      string    `json:"summary"`
}

func RenderJSON(value Report) ([]byte, error) {
	if err := validate(value); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func RenderMarkdown(value Report) (string, error) {
	if err := validate(value); err != nil {
		return "", err
	}
	var out strings.Builder
	fmt.Fprintf(&out, "# Analysis: %s\n\n", md(value.Metadata.Name))
	fmt.Fprintf(&out, "**What is it?** %s\n\n", md(value.Summary))
	fmt.Fprintf(&out, "**What that means:** %s\n\n", md(value.Explanation))
	fmt.Fprintf(&out, "**Target was NOT executed.**\n\n")
	fmt.Fprintf(&out, "## File\n\n- Name: `%s`\n- Path: `%s`\n- Size: %d bytes\n- Modified: %s\n- SHA-256: `%s`\n\n", code(value.Metadata.Name), code(value.Metadata.Path), value.Metadata.Size, value.Metadata.Modified.Format(time.RFC3339), value.Metadata.SHA256)
	fmt.Fprintf(&out, "## Identification\n\n- Format: %s\n- Class: %s\n- Architecture: %s\n", md(value.Identification.Format), md(orNA(value.Identification.Class)), md(value.Identification.Architecture))
	if value.Identification.Endianness != "" {
		fmt.Fprintf(&out, "- Endianness: %s\n", md(value.Identification.Endianness))
	}
	if value.Identification.Subsystem != "" {
		fmt.Fprintf(&out, "- Subsystem: %s\n", md(value.Identification.Subsystem))
	}
	if len(value.Findings) != 0 {
		fmt.Fprintln(&out, "\n## Important observations")
		for _, finding := range value.Findings {
			fmt.Fprintf(&out, "\n### %s\n\n**What it means:** %s\n\n**Why it matters:** %s\n", md(finding.Title), md(finding.Meaning), md(finding.Why))
			if len(finding.Evidence) > 0 {
				fmt.Fprintln(&out, "\nEvidence:")
				for _, item := range finding.Evidence {
					fmt.Fprintf(&out, "- `%s`\n", code(item))
				}
			}
		}
	}
	if len(value.NextSteps) > 0 {
		fmt.Fprintln(&out, "\n## What to investigate next")
		for _, step := range value.NextSteps {
			fmt.Fprintf(&out, "\n- %s", md(step.Action))
			if step.Tool != "" {
				fmt.Fprintf(&out, "\n  - Tool: %s", md(step.Tool))
			}
			if len(step.Learn) > 0 {
				fmt.Fprintln(&out, "\n  - Learn first:")
				for _, item := range step.Learn {
					fmt.Fprintf(&out, "    - %s\n", md(item))
				}
			}
			if len(step.Searches) > 0 {
				fmt.Fprintln(&out, "  - Useful searches:")
				for _, item := range step.Searches {
					fmt.Fprintf(&out, "    - `%s`\n", code(item))
				}
			}
		}
		fmt.Fprintln(&out)
	}
	if len(value.Warnings) > 0 {
		fmt.Fprintln(&out, "## Analyzer warnings")
		for _, warning := range value.Warnings {
			fmt.Fprintf(&out, "- %s\n", md(warning))
		}
		fmt.Fprintln(&out)
	}
	if len(value.Evidence) > 0 {
		fmt.Fprintln(&out, "## Evidence")
		for _, evidence := range value.Evidence {
			fence := fence(evidence.Output)
			fmt.Fprintf(&out, "\n### %s\n\n%stext\n%s", md(evidence.Source), fence, evidence.Output)
			if !strings.HasSuffix(evidence.Output, "\n") {
				out.WriteByte('\n')
			}
			fmt.Fprintf(&out, "%s\n", fence)
		}
	}
	return strings.TrimSpace(out.String()) + "\n", nil
}

func RenderHTML(value Report) (string, error) {
	if err := validate(value); err != nil {
		return "", err
	}
	var out bytes.Buffer
	if err := htmlTemplate.Execute(&out, value); err != nil {
		return "", err
	}
	return out.String(), nil
}

func Save(dir string, value Report) (Paths, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return Paths{}, err
	}
	if value.Metadata.CreatedAt.IsZero() {
		value.Metadata.CreatedAt = time.Now().UTC()
	}
	base := value.Metadata.ID
	if base == "" {
		base = value.Metadata.CreatedAt.UTC().Format("20060102-150405") + "-" + shortHash(value.Metadata.SHA256)
	}
	if !idPattern.MatchString(base) {
		return Paths{}, fmt.Errorf("unsafe report id %q", base)
	}
	for index := 0; index < 100; index++ {
		id := base
		if index > 0 {
			id = fmt.Sprintf("%s-%d", base, index)
		}
		value.Metadata.ID = id
		paths := Paths{Markdown: filepath.Join(dir, id+".md"), JSON: filepath.Join(dir, id+".json"), HTML: filepath.Join(dir, id+".html")}
		if anyExists(paths) {
			continue
		}
		markdown, err := RenderMarkdown(value)
		if err != nil {
			return Paths{}, err
		}
		structured, err := RenderJSON(value)
		if err != nil {
			return Paths{}, err
		}
		page, err := RenderHTML(value)
		if err != nil {
			return Paths{}, err
		}
		written := make([]string, 0, 3)
		for _, file := range []struct{ path, data string }{{paths.Markdown, markdown}, {paths.JSON, string(structured)}, {paths.HTML, page}} {
			if err := atomicWrite(file.path, []byte(file.data), 0644); err != nil {
				for _, name := range written {
					_ = os.Remove(name)
				}
				if os.IsExist(err) {
					break
				}
				return Paths{}, err
			}
			written = append(written, file.path)
		}
		if len(written) == 3 {
			return paths, nil
		}
	}
	return Paths{}, errors.New("could not choose a unique report id")
}

func LoadIndex(dir string) ([]IndexEntry, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	entries := make([]IndexEntry, 0, len(paths))
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		metadata, identification, summary, decodeErr := decodeIndexFields(file)
		closeErr := file.Close()
		if decodeErr != nil {
			continue
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if !idPattern.MatchString(metadata.ID) || metadata.ID != strings.TrimSuffix(filepath.Base(path), ".json") || metadata.Name == "" {
			continue
		}
		created := metadata.CreatedAt
		if created.IsZero() {
			created = metadata.Modified
		}
		entries = append(entries, IndexEntry{ID: metadata.ID, Filename: metadata.Name, HTML: metadata.ID + ".html", Format: identification.Format, Architecture: identification.Architecture, Size: metadata.Size, CreatedAt: created, Summary: summary})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].CreatedAt.Equal(entries[j].CreatedAt) {
			return entries[i].ID > entries[j].ID
		}
		return entries[i].CreatedAt.After(entries[j].CreatedAt)
	})
	return entries, nil
}

func decodeIndexFields(file io.Reader) (Metadata, Identification, string, error) {
	decoder := json.NewDecoder(io.LimitReader(file, maxReportSize))
	start, err := decoder.Token()
	if err != nil {
		return Metadata{}, Identification{}, "", err
	}
	if start != json.Delim('{') {
		return Metadata{}, Identification{}, "", errors.New("report JSON must be an object")
	}
	var metadata Metadata
	var identification Identification
	var summary string
	var haveMetadata, haveIdentification, haveSummary bool
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return Metadata{}, Identification{}, "", err
		}
		key, ok := keyToken.(string)
		if !ok {
			return Metadata{}, Identification{}, "", errors.New("report JSON contains a non-string key")
		}
		switch key {
		case "metadata":
			err = decoder.Decode(&metadata)
			haveMetadata = err == nil
		case "identification":
			err = decoder.Decode(&identification)
			haveIdentification = err == nil
		case "summary":
			err = decoder.Decode(&summary)
			haveSummary = err == nil
		default:
			var discarded json.RawMessage
			err = decoder.Decode(&discarded)
		}
		if err != nil {
			return Metadata{}, Identification{}, "", err
		}
		if haveMetadata && haveIdentification && haveSummary {
			return metadata, identification, summary, nil
		}
	}
	return Metadata{}, Identification{}, "", errors.New("report JSON is missing index fields")
}

func validate(value Report) error {
	if value.TargetExecuted {
		return errors.New("RevKit static analysis reports cannot claim target execution")
	}
	if value.SchemaVersion != 1 || value.Metadata.Name == "" || value.Metadata.Size < 0 || value.Identification.Format == "" || value.Identification.Architecture == "" || value.Summary == "" || value.Explanation == "" {
		return errors.New("report is missing required identification or summary fields")
	}
	return nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".revkit-report-*.tmp")
	if err != nil {
		return err
	}
	temp := file.Name()
	defer os.Remove(temp)
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Chmod(mode); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Link(temp, path)
}

func anyExists(paths Paths) bool {
	for _, path := range []string{paths.Markdown, paths.JSON, paths.HTML} {
		if _, err := os.Lstat(path); err == nil {
			return true
		}
	}
	return false
}

func shortHash(hash string) string {
	hash = strings.TrimPrefix(hash, "sha256:")
	if len(hash) > 8 {
		return hash[:8]
	}
	return hash
}

func md(value string) string {
	value = strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ", "\t", " ").Replace(value)
	value = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(value)
	var out strings.Builder
	for _, character := range value {
		if strings.ContainsRune("\\`*_{}[]()#+-.!|", character) {
			out.WriteByte('\\')
		}
		out.WriteRune(character)
	}
	return out.String()
}

func code(value string) string {
	return strings.NewReplacer("`", "'", "\r\n", " ", "\n", " ", "\r", " ", "\t", " ").Replace(value)
}

func fence(value string) string {
	longest, current := 0, 0
	for _, char := range value {
		if char == '`' {
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

func orNA(value string) string {
	if strings.TrimSpace(value) == "" {
		return "n/a"
	}
	return value
}

var htmlTemplate = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>RevKit</title>
  <style>
    :root{color-scheme:dark;background:#10151d;color:#e8edf4;font:16px/1.6 system-ui,sans-serif}
    body{margin:0 auto;max-width:960px;padding:32px 20px 64px}
    header,.card{background:#171f2a;border:1px solid #293646;border-radius:12px;padding:20px;margin:16px 0}
    h1,h2,h3{line-height:1.25}h1{margin:0;font-size:1.8rem}h2{margin-top:32px}
    .muted{color:#a6b4c5}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
    .label{color:#9fb0c5;font-size:.82rem;text-transform:uppercase;letter-spacing:.08em}
    code,pre{font-family:ui-monospace,monospace;background:#0d1218;border-radius:6px}
    code{padding:2px 5px}pre{padding:14px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere}
    a{color:#82b8ff}.finding{border-left:3px solid #77a9e8;padding-left:16px}
  </style>
</head>
<body>
  <header><h1>RevKit</h1><p>{{.Summary}}</p><p class="muted">Target was NOT executed.</p></header>
  <section class="card"><h2>What that means</h2><p>{{.Explanation}}</p></section>
  <section class="card grid">
    <div><div class="label">File</div>{{.Metadata.Name}}</div>
    <div><div class="label">Format</div>{{.Identification.Format}} {{.Identification.Class}}</div>
    <div><div class="label">Architecture</div>{{.Identification.Architecture}}</div>
    <div><div class="label">Size</div>{{.Metadata.Size}} bytes</div>
    <div><div class="label">SHA-256</div><code>{{.Metadata.SHA256}}</code></div>
    <div><div class="label">Path</div><code>{{.Metadata.Path}}</code></div>
  </section>
  {{if .Findings}}<h2>Important observations</h2>{{range .Findings}}
    <article class="card finding"><h3>{{.Title}}</h3><p><strong>What it means</strong><br>{{.Meaning}}</p><p><strong>Why it matters</strong><br>{{.Why}}</p>{{if .Evidence}}<p class="muted">Evidence: {{range $i,$item := .Evidence}}{{if $i}} · {{end}}<code>{{$item}}</code>{{end}}</p>{{end}}</article>
  {{end}}{{end}}
  {{if .NextSteps}}<h2>What to investigate next</h2>{{range .NextSteps}}
    <article class="card"><p>{{.Action}}</p>{{if .Tool}}<p><strong>Tool</strong>: {{.Tool}}</p>{{end}}{{if .Learn}}<p><strong>Learn first</strong></p><ul>{{range .Learn}}<li>{{.}}</li>{{end}}</ul>{{end}}{{if .Searches}}<p><strong>Useful searches</strong></p><ul>{{range .Searches}}<li><code>{{.}}</code></li>{{end}}</ul>{{end}}</article>
  {{end}}{{end}}
  {{if .Warnings}}<h2>Analyzer warnings</h2><ul>{{range .Warnings}}<li>{{.}}</li>{{end}}</ul>{{end}}
  {{if .Evidence}}<h2>Evidence</h2>{{range .Evidence}}<details class="card"><summary>Raw evidence: {{.Source}}</summary><pre>{{.Output}}</pre></details>{{end}}{{end}}
</body>
</html>
`))
