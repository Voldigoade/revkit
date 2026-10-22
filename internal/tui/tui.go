package tui

import (
	"fmt"
	"strings"

	"charm.land/bubbles/v2/filepicker"
	tea "charm.land/bubbletea/v2"
)

var menu = []string{"Analyze a file", "Reports", "Tools", "Update", "Doctor", "Open dashboard", "Exit"}

type Item struct {
	Title  string
	Detail string
	Path   string
}

type Options struct {
	Reports []Item
	Tools   []Item
}

type Result struct {
	Action string
	Target string
}

type model struct {
	options  Options
	page     string
	selected int
	picker   filepicker.Model
	report   int
	result   Result
}

func New(options Options) *model {
	picker := filepicker.New()
	picker.ShowHidden = false
	picker.FileAllowed = true
	picker.DirAllowed = false
	picker.SetHeight(15)
	return &model{options: options, picker: picker}
}

func Run(options Options) (Result, error) {
	final, err := tea.NewProgram(New(options)).Run()
	if err != nil {
		return Result{}, err
	}
	return final.(*model).result, nil
}

func (m *model) Init() tea.Cmd { return nil }

func (m *model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	if m.page == "picker" {
		if selected, path := m.picker.DidSelectFile(message); selected {
			m.result = Result{Action: "analyze", Target: path}
			return m, tea.Quit
		}
		var command tea.Cmd
		m.picker, command = m.picker.Update(message)
		if key, ok := message.(tea.KeyPressMsg); ok && key.String() == "esc" {
			m.page = "menu"
			return m, nil
		}
		return m, command
	}
	key, ok := message.(tea.KeyPressMsg)
	if !ok {
		return m, nil
	}
	switch m.page {
	case "reports":
		switch key.String() {
		case "up":
			if m.report > 0 {
				m.report--
			}
		case "down":
			if m.report < len(m.options.Reports)-1 {
				m.report++
			}
		case "enter":
			if len(m.options.Reports) > 0 {
				item := m.options.Reports[m.report]
				m.result = Result{Action: "open-report", Target: item.Path}
				return m, tea.Quit
			}
		case "esc", "q":
			m.page = "menu"
		}
		return m, nil
	case "tools":
		if key.String() == "esc" || key.String() == "q" || key.String() == "enter" {
			m.page = "menu"
		}
		return m, nil
	}
	switch key.String() {
	case "up":
		if m.selected > 0 {
			m.selected--
		}
	case "down":
		if m.selected < len(menu)-1 {
			m.selected++
		}
	case "q", "ctrl+c":
		return m, tea.Quit
	case "enter":
		switch m.selected {
		case 0:
			m.page = "picker"
			return m, m.picker.Init()
		case 1:
			m.page, m.report = "reports", 0
		case 2:
			m.page = "tools"
		case 3:
			m.result.Action = "update"
			return m, tea.Quit
		case 4:
			m.result.Action = "doctor"
			return m, tea.Quit
		case 5:
			m.result.Action = "dashboard"
			return m, tea.Quit
		case 6:
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m *model) View() tea.View {
	var view strings.Builder
	view.WriteString("RevKit\n\n")
	switch m.page {
	case "picker":
		view.WriteString("Analyze a file\nChoose a file. It will not be executed. Press Esc to return.\n\n")
		view.WriteString(m.picker.View())
	case "reports":
		view.WriteString("Reports\n\n")
		if len(m.options.Reports) == 0 {
			view.WriteString("No reports yet. Analyze a file to get started.\n")
		} else {
			for index, item := range m.options.Reports {
				cursor := "  "
				if index == m.report {
					cursor = "> "
				}
				fmt.Fprintf(&view, "%s%s  %s\n", cursor, item.Title, item.Detail)
			}
			view.WriteString("\nEnter opens the selected report. Esc returns to the menu.\n")
		}
	case "tools":
		view.WriteString("Tools\n\n")
		for _, item := range m.options.Tools {
			fmt.Fprintf(&view, "%-20s %s\n", item.Title, item.Detail)
		}
		view.WriteString("\nPress Enter or Esc to return.\n")
	default:
		view.WriteString("Small, static-first reverse-engineering workstation\n\n")
		for index, item := range menu {
			cursor := "  "
			if index == m.selected {
				cursor = "> "
			}
			view.WriteString(cursor + item + "\n")
		}
		view.WriteString("\nUse Up and Down, then Enter. Press q to quit.\n")
	}
	result := tea.NewView(view.String())
	result.AltScreen = true
	return result
}
