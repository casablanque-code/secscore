package printer

import (
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"secscore/internal/model"
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

func isTerminal(fd uintptr) bool {
	var termios syscall.Termios
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCGETS, uintptr(unsafe.Pointer(&termios)))
	return err == 0
}

func terminalWidth(fd uintptr) int {
	type winsize struct {
		Row, Col, Xpixel, Ypixel uint16
	}
	var ws winsize
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, fd, 0x5413 /* TIOCGWINSZ */, uintptr(unsafe.Pointer(&ws)))
	if err == 0 && ws.Col > 0 {
		return int(ws.Col)
	}
	return 80
}

type p struct {
	w     io.Writer
	color bool
	width int
}

func newP(w io.Writer) *p {
	pr := &p{w: w, width: 80}
	if f, ok := w.(*os.File); ok {
		fd := f.Fd()
		pr.color = isTerminal(fd)
		if pr.color {
			pr.width = terminalWidth(fd)
		}
	}
	// cap width for readability
	if pr.width > 100 {
		pr.width = 100
	}
	return pr
}

func (pr *p) c(code, text string) string {
	if !pr.color {
		return text
	}
	return code + text + colorReset
}

func (pr *p) rule(char string) string {
	return strings.Repeat(char, pr.width)
}

func (pr *p) severityStyle(s model.Severity) (icon, col string) {
	switch s {
	case model.SeverityCritical:
		return "✖", colorRed
	case model.SeverityWarning:
		return "▲", colorYellow
	default:
		return "●", colorCyan
	}
}

func PrintReport(w io.Writer, report model.Report) {
	pr := newP(w)

	// ── Header ───────────────────────────────────────────────────────────────
	fmt.Fprintln(pr.w, pr.c(colorDim, pr.rule("─")))
	fmt.Fprintf(pr.w, "  %s\n", pr.c(colorBold+colorWhite, "secscore  —  local security report"))
	fmt.Fprintln(pr.w, pr.c(colorDim, pr.rule("─")))
	fmt.Fprintln(pr.w)

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
	bar := strings.Repeat("█", filled) + pr.c(colorDim, strings.Repeat("░", barWidth-filled))

	fmt.Fprintf(pr.w, "  Score   %s  %s  %s\n",
		pr.c(scoreColor+colorBold, fmt.Sprintf("%3d/100", score)),
		bar,
		pr.c(scoreColor, scoreLabel),
	)
	fmt.Fprintln(pr.w)

	// ── Summary counts ───────────────────────────────────────────────────────
	var critical, warnings, info int
	for _, f := range report.Findings {
		switch f.Severity {
		case model.SeverityCritical:
			critical++
		case model.SeverityWarning:
			warnings++
		default:
			info++
		}
	}

	fmt.Fprintf(pr.w, "  %s   %s   %s\n",
		pr.c(colorRed+colorBold, fmt.Sprintf("✖  %d critical", critical)),
		pr.c(colorYellow+colorBold, fmt.Sprintf("▲  %d warning", warnings)),
		pr.c(colorCyan, fmt.Sprintf("●  %d info", info)),
	)

	if len(report.Findings) == 0 {
		fmt.Fprintln(pr.w)
		fmt.Fprintf(pr.w, "\n  %s\n\n", pr.c(colorGreen+colorBold, "✔  No issues found."))
		fmt.Fprintln(pr.w, pr.c(colorDim, pr.rule("─")))
		return
	}

	// ── Sections ─────────────────────────────────────────────────────────────
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
		var group []model.Finding
		for _, f := range report.Findings {
			if f.Severity == sec.sev {
				group = append(group, f)
			}
		}
		if len(group) == 0 {
			continue
		}

		fmt.Fprintln(pr.w)
		fmt.Fprintln(pr.w, pr.c(sec.col+colorBold, pr.rule("─")))
		fmt.Fprintf(pr.w, "%s\n", pr.c(sec.col+colorBold, sec.label))
		fmt.Fprintln(pr.w, pr.c(sec.col+colorBold, pr.rule("─")))

		for _, f := range group {
			icon, col := pr.severityStyle(f.Severity)

			fmt.Fprintln(pr.w)
			// Title line
			fmt.Fprintf(pr.w, "  %s  %s\n",
				pr.c(col+colorBold, icon),
				pr.c(colorBold, f.Title),
			)
			// Description
			fmt.Fprintf(pr.w, "     %s\n",
				pr.c(colorDim, wordWrap(f.Description, pr.width-6)),
			)
			// Fix
			fmt.Fprintf(pr.w, "     %s  %s\n",
				pr.c(colorGray, "fix:"),
				wordWrap(f.Recommendation, pr.width-11),
			)
			// Evidence
			for _, ev := range f.Evidence {
				fmt.Fprintf(pr.w, "     %s  %s  %s\n",
					pr.c(colorGray, "src:"),
					pr.c(colorDim, ev.Source),
					pr.c(colorDim, truncate(ev.Details, 60)),
				)
			}
		}
	}

	fmt.Fprintln(pr.w)
	fmt.Fprintln(pr.w, pr.c(colorDim, pr.rule("─")))
	fmt.Fprintln(pr.w)
}

func wordWrap(text string, width int) string {
	if width <= 0 || len(text) <= width {
		return text
	}
	words := strings.Fields(text)
	var lines []string
	line := ""
	for _, w := range words {
		if line == "" {
			line = w
		} else if len(line)+1+len(w) <= width {
			line += " " + w
		} else {
			lines = append(lines, line)
			line = strings.Repeat(" ", 9) + w // indent continuation
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
