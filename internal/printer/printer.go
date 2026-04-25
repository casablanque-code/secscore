package printer

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/casablanque-code/secscore/internal/model"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorGreen  = "\033[32m"
	colorWhite  = "\033[97m"
	colorGray   = "\033[90m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)



type pr struct {
	w     io.Writer
	color bool
	width int
}

func newPr(w io.Writer) *pr {
	p := &pr{w: w, width: 80}
	if f, ok := w.(*os.File); ok {
		fd := f.Fd()
		p.color = isTerminal(fd)
		if p.color {
			p.width = terminalWidth(fd)
		}
	}
	if p.width > 100 {
		p.width = 100
	}
	return p
}

func (p *pr) c(code, text string) string {
	if !p.color {
		return text
	}
	return code + text + colorReset
}

func (p *pr) rule(char string) string {
	return strings.Repeat(char, p.width)
}

// PrintProgress writes a single scanning status line, overwriting the previous one.
// Call PrintProgressDone when scanning is complete to move to a new line.
func PrintProgress(w io.Writer, scannerName string) {
	p := newPr(w)
	if !p.color {
		return // don't clutter non-tty output
	}
	fmt.Fprintf(w, "\r  %s scanning %-16s",
		p.c(colorDim, "▸"),
		p.c(colorDim, scannerName+"..."),
	)
}

// PrintProgressDone clears the progress line.
func PrintProgressDone(w io.Writer) {
	p := newPr(w)
	if !p.color {
		return
	}
	fmt.Fprintf(w, "\r%s\r", strings.Repeat(" ", p.width))
}

func PrintReport(w io.Writer, report model.Report) {
	p := newPr(w)

	// ── Header ───────────────────────────────────────────────────────────────
	fmt.Fprintln(p.w, p.c(colorDim, p.rule("─")))
	fmt.Fprintf(p.w, "  %s\n", p.c(colorBold+colorWhite, "secscore  —  local security report"))
	fmt.Fprintln(p.w, p.c(colorDim, p.rule("─")))
	fmt.Fprintln(p.w)

	// ── Score bar ────────────────────────────────────────────────────────────
	score := report.Score
	var scoreColor, scoreLabel string
	switch {
	case score >= 90:
		scoreColor, scoreLabel = colorGreen, "Excellent"
	case score >= 75:
		scoreColor, scoreLabel = colorCyan, "Good"
	case score >= 50:
		scoreColor, scoreLabel = colorYellow, "Needs improvement"
	default:
		scoreColor, scoreLabel = colorRed, "High risk"
	}

	barWidth := 36
	filled := score * barWidth / 100
	if filled > barWidth {
		filled = barWidth
	}
	bar := strings.Repeat("█", filled) + p.c(colorDim, strings.Repeat("░", barWidth-filled))

	fmt.Fprintf(p.w, "  Score   %s  %s  %s\n",
		p.c(scoreColor+colorBold, fmt.Sprintf("%3d/100", score)),
		bar,
		p.c(scoreColor, scoreLabel),
	)
	fmt.Fprintln(p.w)

	// ── Summary counts ───────────────────────────────────────────────────────
	var nCritical, nWarning, nInfo int
	for _, f := range report.Findings {
		switch f.Severity {
		case model.SeverityCritical:
			nCritical++
		case model.SeverityWarning:
			nWarning++
		default:
			nInfo++
		}
	}

	fmt.Fprintf(p.w, "  %s   %s   %s\n",
		p.c(colorRed+colorBold, fmt.Sprintf("✖  %d critical", nCritical)),
		p.c(colorYellow+colorBold, fmt.Sprintf("▲  %d warning", nWarning)),
		p.c(colorCyan, fmt.Sprintf("●  %d info", nInfo)),
	)

	if len(report.Findings) == 0 {
		fmt.Fprintf(p.w, "\n  %s\n\n", p.c(colorGreen+colorBold, "✔  No issues found."))
		fmt.Fprintln(p.w, p.c(colorDim, p.rule("─")))
		return
	}

	// ── Findings grouped: severity first, then by category ───────────────────
	sections := []struct {
		sev   model.Severity
		label string
		col   string
	}{
		{model.SeverityCritical, "  CRITICAL", colorRed},
		{model.SeverityWarning, "  WARNINGS", colorYellow},
		{model.SeverityInfo, "  INFO", colorCyan},
	}

	for _, sec := range sections {
		// Group findings in this severity by category
		byCategory := groupByCategory(report.Findings, sec.sev)
		if len(byCategory) == 0 {
			continue
		}

		fmt.Fprintln(p.w)
		fmt.Fprintln(p.w, p.c(sec.col+colorBold, p.rule("─")))
		fmt.Fprintf(p.w, "%s\n", p.c(sec.col+colorBold, sec.label))
		fmt.Fprintln(p.w, p.c(sec.col+colorBold, p.rule("─")))

		// Print categories in order
		for _, cat := range categoryOrder {
			findings, ok := byCategory[cat]
			if !ok {
				continue
			}
			// Category header if more than one category present
			if len(byCategory) > 1 {
				fmt.Fprintf(p.w, "\n  %s\n", p.c(colorGray, categoryLabel(cat)))
			}
			for _, f := range findings {
				printFinding(p, f)
			}
		}
	}

	fmt.Fprintln(p.w)
	fmt.Fprintln(p.w, p.c(colorDim, p.rule("─")))
	fmt.Fprintln(p.w)
}

func printFinding(p *pr, f model.Finding) {
	var icon, col string
	switch f.Severity {
	case model.SeverityCritical:
		icon, col = "✖", colorRed
	case model.SeverityWarning:
		icon, col = "▲", colorYellow
	default:
		icon, col = "●", colorCyan
	}

	fmt.Fprintln(p.w)
	fmt.Fprintf(p.w, "  %s  %s\n",
		p.c(col+colorBold, icon),
		p.c(colorBold, f.Title),
	)
	fmt.Fprintf(p.w, "     %s\n", p.c(colorDim, wordWrap(f.Description, p.width-6)))
	fmt.Fprintf(p.w, "     %s  %s\n",
		p.c(colorGray, "fix:"),
		wordWrap(f.Recommendation, p.width-11),
	)
	for _, ev := range f.Evidence {
		fmt.Fprintf(p.w, "     %s  %s  %s\n",
			p.c(colorGray, "src:"),
			p.c(colorDim, ev.Source),
			p.c(colorDim, truncate(ev.Details, 60)),
		)
	}
}

// category classification

type category int

const (
	catSSH category = iota
	catFirewall
	catDocker
	catKernel
	catSudo
	catFiles
	catOther
)

var categoryOrder = []category{catSSH, catFirewall, catDocker, catKernel, catSudo, catFiles, catOther}

func categoryLabel(c category) string {
	switch c {
	case catSSH:
		return "SSH"
	case catFirewall:
		return "Firewall"
	case catDocker:
		return "Docker / Services"
	case catKernel:
		return "Kernel (sysctl)"
	case catSudo:
		return "Sudo"
	case catFiles:
		return "Filesystem"
	default:
		return "Other"
	}
}

func findingCategory(f model.Finding) category {
	id := f.ID
	switch {
	case strings.HasPrefix(id, "sshd-"):
		return catSSH
	case strings.HasPrefix(id, "ufw-"):
		return catFirewall
	case strings.HasPrefix(id, "exposed-") || strings.HasPrefix(id, "protected-") ||
		strings.HasPrefix(id, "proxy-") || strings.HasPrefix(id, "http-"):
		return catDocker
	case strings.HasPrefix(id, "sysctl-"):
		return catKernel
	case strings.HasPrefix(id, "sudo-"):
		return catSudo
	case strings.HasPrefix(id, "world-writable"):
		return catFiles
	default:
		return catOther
	}
}

func groupByCategory(findings []model.Finding, sev model.Severity) map[category][]model.Finding {
	result := make(map[category][]model.Finding)
	for _, f := range findings {
		if f.Severity != sev {
			continue
		}
		cat := findingCategory(f)
		result[cat] = append(result[cat], f)
	}
	return result
}

func wordWrap(text string, width int) string {
	if width <= 0 || len(text) <= width {
		return text
	}
	words := strings.Fields(text)
	var lines []string
	line := ""
	indent := strings.Repeat(" ", 9)
	for _, w := range words {
		if line == "" {
			line = w
		} else if len(line)+1+len(w) <= width {
			line += " " + w
		} else {
			lines = append(lines, line)
			line = indent + w
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
