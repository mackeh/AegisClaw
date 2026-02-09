package approval

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/mackeh/AegisClaw/internal/scope"
)

// Styles
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#7D56F4")).
			Padding(0, 1)

	scopeStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#04B575"))

	riskCriticalStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#FF0000")).
				Bold(true)

	riskHighStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF8700")).
			Bold(true)

	riskMediumStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFF00"))

	riskLowStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00FF00"))

	subtleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("241"))
)

type Model struct {
	Request scope.ScopeRequest
	Choice  string
	Quitting bool
}

func NewModel(req scope.ScopeRequest) Model {
	return Model{
		Request: req,
		Choice:  "",
	}
}

func (m Model) Init() tea.Cmd {
	return nil
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "y", "Y":
			m.Choice = "approve"
			m.Quitting = true
			return m, tea.Quit
		case "n", "N":
			m.Choice = "deny"
			m.Quitting = true
			return m, tea.Quit
		case "a", "A":
			m.Choice = "always"
			m.Quitting = true
			return m, tea.Quit
		case "ctrl+c", "q":
			m.Choice = "deny"
			m.Quitting = true
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m Model) View() string {
	if m.Choice != "" {
		return fmt.Sprintf("\n  Decision: %s\n\n", m.Choice)
	}

	s := strings.Builder{}

	// Header
	maxRisk := m.Request.MaxRisk()
	riskBadge := renderRiskBadge(maxRisk)
	
	s.WriteString(fmt.Sprintf("\n%s %s\n\n", titleStyle.Render(" PERMISSION REQUEST "), riskBadge))
	
	s.WriteString(fmt.Sprintf("  %s is requesting access:\n\n", lipgloss.NewStyle().Bold(true).Render(m.Request.RequestedBy)))

	// Scopes
	for _, sc := range m.Request.Scopes {
		s.WriteString(fmt.Sprintf("  • %s %s\n", renderRiskEmoji(sc.RiskLevel), sc.String()))
	}
	
	s.WriteString(fmt.Sprintf("\n  %s\n", subtleStyle.Render(m.Request.Reason)))

	// Controls
	s.WriteString("\n  [Y] Approve once   [A] Always allow   [N] Deny\n\n")

	return s.String()
}

func renderRiskBadge(r scope.Risk) string {
	switch r {
	case scope.RiskCritical:
		return riskCriticalStyle.Render("CRITICAL RISK")
	case scope.RiskHigh:
		return riskHighStyle.Render("HIGH RISK")
	case scope.RiskMedium:
		return riskMediumStyle.Render("MEDIUM RISK")
	default:
		return riskLowStyle.Render("LOW RISK")
	}
}

func renderRiskEmoji(r scope.Risk) string {
	switch r {
	case scope.RiskCritical:
		return "🔴"
	case scope.RiskHigh:
		return "🟠"
	case scope.RiskMedium:
		return "🟡"
	default:
		return "🟢"
	}
}

// RequestApproval launches the TUI to ask for approval
// Returns: "approve", "deny", "always", or error
func RequestApproval(req scope.ScopeRequest) (string, error) {
	p := tea.NewProgram(NewModel(req))
	m, err := p.Run()
	if err != nil {
		return "deny", err
	}

	if model, ok := m.(Model); ok {
		return model.Choice, nil
	}
	return "deny", nil
}
