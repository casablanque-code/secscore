package fixer

import (
	"bufio"
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
	colorGreen  = "\033[32m"
	colorGray   = "\033[90m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

// RunInteractive walks fixable findings, prompts user, applies fixes.
// Returns number of fixes applied.
func RunInteractive(findings []model.Finding, dryRun bool, out io.Writer) int {
	fixable := fixableFindings(findings)
	if len(fixable) == 0 {
		fmt.Fprintf(out, "\n  %s\n\n", green("✔  No fixable issues found."))
		return 0
	}

	if dryRun {
		fmt.Fprintf(out, "\n  %s\n\n", dim("Dry-run mode — no changes will be made.\n"))
	}

	fmt.Fprintf(out, "\n  %s fixable issue(s) found.\n\n", bold(fmt.Sprintf("%d", len(fixable))))

	applied := 0
	reader := bufio.NewReader(os.Stdin)

	for i, f := range fixable {
		sevColor := colorYellow
		if f.Severity == model.SeverityCritical {
			sevColor = colorRed
		}

		fmt.Fprintf(out, "  [%d/%d] %s%s%s  %s\n",
			i+1, len(fixable),
			sevColor+colorBold, string(f.Severity), colorReset,
			bold(f.Title),
		)
		fmt.Fprintf(out, "         %s\n", dim(f.Fix.Description))
		fmt.Fprintf(out, "         Actions:\n")
		for _, a := range f.Fix.Actions {
			fmt.Fprintf(out, "           %s %s\n", dim("▸"), dim(actionDesc(a)))
		}
		fmt.Fprintln(out)

		if dryRun {
			fmt.Fprintf(out, "  %s would apply\n\n", dim("[dry-run]"))
			applied++
			continue
		}

		fmt.Fprintf(out, "  Apply? [y/N/q] ")
		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(strings.ToLower(line))

		switch line {
		case "y", "yes":
			results := Apply(f.Fix, false)
			printResults(out, results)
			applied++
		case "q", "quit":
			fmt.Fprintf(out, "\n  %s\n\n", dim("Aborted."))
			return applied
		default:
			fmt.Fprintf(out, "  %s\n\n", dim("Skipped."))
		}
	}

	fmt.Fprintln(out)
	if dryRun {
		fmt.Fprintf(out, "  %s fixes would be applied (dry-run)\n\n", bold(fmt.Sprintf("%d", applied)))
	} else {
		fmt.Fprintf(out, "  %s fix(es) applied.\n\n", green(fmt.Sprintf("%d", applied)))
		if applied > 0 {
			fmt.Fprintf(out, "  %s\n\n", dim("Run secscore again to verify the changes."))
		}
	}

	return applied
}

// RunAuto applies all fixes without prompting.
func RunAuto(findings []model.Finding, dryRun bool, out io.Writer) int {
	fixable := fixableFindings(findings)
	if len(fixable) == 0 {
		fmt.Fprintf(out, "no fixable issues\n")
		return 0
	}

	applied := 0
	for _, f := range fixable {
		results := Apply(f.Fix, dryRun)
		ok := true
		for _, r := range results {
			if r.Err != nil {
				fmt.Fprintf(out, "  ✖  %s: %v\n", f.ID, r.Err)
				ok = false
			}
		}
		if ok {
			applied++
			fmt.Fprintf(out, "  ✔  %s\n", f.ID)
		}
	}
	return applied
}

func fixableFindings(findings []model.Finding) []model.Finding {
	var out []model.Finding
	for _, f := range findings {
		if f.Fix != nil && len(f.Fix.Actions) > 0 {
			// Only fix CRITICAL and WARNING — not INFO
			if f.Severity == model.SeverityCritical || f.Severity == model.SeverityWarning {
				out = append(out, f)
			}
		}
	}
	return out
}

func printResults(out io.Writer, results []Result) {
	for _, r := range results {
		if r.Err != nil {
			fmt.Fprintf(out, "  %s✖%s  %s: %v\n", colorRed, colorReset, actionDesc(r.Action), r.Err)
		} else {
			fmt.Fprintf(out, "  %s✔%s  %s\n", colorGreen, colorReset, r.Detail)
		}
	}
	fmt.Fprintln(out)
}

func actionDesc(a model.Action) string {
	switch a.Kind {
	case model.ActionFileEdit:
		return fmt.Sprintf("edit %s: set %q", a.File, a.Replace)
	case model.ActionSysctlSet:
		return fmt.Sprintf("sysctl %s=%s", a.Key, a.Value)
	case model.ActionCommand:
		return strings.Join(a.Cmd, " ")
	default:
		return string(a.Kind)
	}
}

func bold(s string) string  { return colorBold + s + colorReset }
func dim(s string) string   { return colorDim + s + colorReset }
func green(s string) string { return colorGreen + colorBold + s + colorReset }
