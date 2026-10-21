package dashboard

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"os"
	"path/filepath"

	"github.com/Voldigoade/revkit/internal/catalog"
)

//go:embed template.html
var assets embed.FS

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

type page struct {
	Tools []viewTool
}

func Render(c catalog.Catalog, statuses map[string]ToolStatus) (string, error) {
	tmpl, err := template.ParseFS(assets, "template.html")
	if err != nil {
		return "", err
	}
	data := page{}
	for _, tool := range c.Tools {
		status, ok := statuses[tool.ID]
		if !ok {
			status = ToolStatus{Status: "missing", Version: "—"}
		}
		if status.Version == "" {
			status.Version = "—"
		}
		data.Tools = append(data.Tools, viewTool{Tool: tool, Status: status.Status, Version: status.Version, Path: status.Path})
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
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
