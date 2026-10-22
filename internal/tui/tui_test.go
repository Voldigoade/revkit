package tui

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

func TestMenuNavigationAndReportList(t *testing.T) {
	m := New(Options{Reports: []Item{{Title: "sample.exe", Detail: "PE x86-64", Path: "/reports/sample.html"}}})
	if !strings.Contains(m.View().Content, "> Analyze a file") {
		t.Fatal("initial menu selection is missing")
	}
	updated, _ := m.Update(tea.KeyPressMsg(tea.Key{Code: tea.KeyDown}))
	m = updated.(*model)
	if !strings.Contains(m.View().Content, "> Reports") {
		t.Fatal("down arrow did not change the selected menu item")
	}
	updated, _ = m.Update(tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
	m = updated.(*model)
	if !strings.Contains(m.View().Content, "> sample.exe  PE x86-64") {
		t.Fatal("Enter did not open the report list")
	}
}

func TestAnalyzeMenuOpensFilePicker(t *testing.T) {
	m := New(Options{})
	updated, command := m.Update(tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
	m = updated.(*model)
	if command == nil || !strings.Contains(m.View().Content, "Choose a file") {
		t.Fatal("Analyze a file did not open the file picker")
	}
}
