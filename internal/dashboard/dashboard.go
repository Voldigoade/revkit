package dashboard

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"regexp"

	"github.com/Voldigoade/revkit/internal/catalog"
	"github.com/Voldigoade/revkit/internal/report"
)

//go:embed template.html
var assets embed.FS

var reportIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,95}$`)

type ToolStatus struct {
	Status  string
	Version string
	Path    string
}

type viewTool struct {
	catalog.Tool
	Status  string
	Version string
	Path    string
}

type viewReport struct {
	report.IndexEntry
	SizeLabel string
	DateLabel string
}

type page struct {
	Tools   []viewTool
	Reports []viewReport
}

func Render(c catalog.Catalog, statuses map[string]ToolStatus, reports []report.IndexEntry) (string, error) {
	tmpl, err := template.ParseFS(assets, "template.html")
	if err != nil {
		return "", err
	}
	data := page{}
	for _, tool := range c.Tools {
		status, ok := statuses[tool.ID]
		if !ok {
			status = ToolStatus{Status: "missing", Version: "n/a"}
		}
		if status.Version == "" {
			status.Version = "n/a"
		}
		data.Tools = append(data.Tools, viewTool{Tool: tool, Status: status.Status, Version: status.Version, Path: status.Path})
	}
	for _, entry := range reports {
		if !reportIDPattern.MatchString(entry.ID) {
			continue
		}
		entry.HTML = entry.ID + ".html"
		dateLabel := "n/a"
		if !entry.CreatedAt.IsZero() {
			dateLabel = entry.CreatedAt.UTC().Format("2006-01-02 15:04 UTC")
		}
		data.Reports = append(data.Reports, viewReport{IndexEntry: entry, SizeLabel: formatBytes(entry.Size), DateLabel: dateLabel})
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func formatBytes(size int64) string {
	value := fmt.Sprintf("%d", size)
	for index := len(value) - 3; index > 0; index -= 3 {
		value = value[:index] + "," + value[index:]
	}
	return value + " bytes"
}

func Write(root, content string) error {
	dest := filepath.Join(root, "dashboard", "index.html")
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return err
	}
	if current, err := os.ReadFile(dest); err == nil && bytes.Equal(current, []byte(content)) {
		return nil
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".dashboard-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.WriteString(content); err != nil {
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
	if err := os.Rename(name, dest); err != nil {
		return fmt.Errorf("write dashboard: %w", err)
	}
	return nil
}
