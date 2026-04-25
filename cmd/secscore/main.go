package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/casablanque-code/secscore/internal/engine"
	"github.com/casablanque-code/secscore/internal/fixer"
	"github.com/casablanque-code/secscore/internal/model"
	"github.com/casablanque-code/secscore/internal/printer"
	"github.com/casablanque-code/secscore/internal/rule"
	"github.com/casablanque-code/secscore/internal/scanner"
	"github.com/casablanque-code/secscore/internal/version"
)

func main() {
	var (
		jsonOutput  bool
		only        string
		showVersion bool
		profilesPath string
		fix         bool
		fixAuto     bool
		fixDryRun   bool
	)

	flag.BoolVar(&jsonOutput, "json", false, "")
	flag.StringVar(&only, "only", "", "")
	flag.StringVar(&profilesPath, "profiles", "", "")
	flag.BoolVar(&showVersion, "version", false, "")
	flag.BoolVar(&fix, "fix", false, "")
	flag.BoolVar(&fixAuto, "auto", false, "")
	flag.BoolVar(&fixDryRun, "dry-run", false, "")

	flag.Usage = printHelp
	flag.Parse()

	if showVersion {
		fmt.Printf("secscore %s\n", version.Version)
		return
	}

	if flag.NArg() > 0 && flag.Arg(0) == "help" {
		printHelp()
		return
	}

	isRoot := os.Geteuid() == 0
	if !isRoot && !jsonOutput {
		fmt.Fprintln(os.Stderr, "⚠  Running without root. ss process info, sudo and sysctl reads may be incomplete.")
		fmt.Fprintln(os.Stderr, "   Run with sudo for full results.")
		fmt.Fprintln(os.Stderr)
	}

	if fix && !isRoot {
		fmt.Fprintln(os.Stderr, "✖  --fix requires root.")
		os.Exit(1)
	}

	if profilesPath == "" {
		profilesPath = resolveProfilesPath()
	}
	if err := model.LoadProfiles(profilesPath); err != nil && !jsonOutput {
		fmt.Fprintf(os.Stderr, "⚠  profiles.yaml not loaded: %v\n", err)
		fmt.Fprintln(os.Stderr)
	}

	scanners := buildScanners(only)

	rules := []rule.Rule{
		rule.NewServiceExposureRule(),
		rule.NewHTTPAuthRule(),
		rule.NewProtectionRule(),
		rule.NewUFWCorrelationRule(),
		rule.NewSSHDRule(),
		rule.NewSysctlRule(),
		rule.NewSudoRule(),
		rule.NewWorldWritableRule(),
	}

	eng := engine.New(scanners, rules)

	if !jsonOutput {
		eng.WithProgress(func(name string) {
			printer.PrintProgress(os.Stderr, name)
		})
	}

	report, err := eng.Run(isRoot)
	printer.PrintProgressDone(os.Stderr)

	if err != nil {
		fmt.Fprintf(os.Stderr, "secscore: %v\n", err)
		os.Exit(1)
	}

	if jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(report)
		return
	}

	printer.PrintReport(os.Stdout, report)

	// ── Fix mode ─────────────────────────────────────────────────────────────
	if fix {
		if fixAuto {
			fixer.RunAuto(report.Findings, fixDryRun, os.Stdout)
		} else {
			fixer.RunInteractive(report.Findings, fixDryRun, os.Stdout)
		}
		return
	}

	if report.HasCritical() {
		os.Exit(2)
	}
	if report.HasWarning() {
		os.Exit(1)
	}
}

func buildScanners(only string) []scanner.Scanner {
	all := map[string]scanner.Scanner{
		"docker":         scanner.NewDockerScanner(),
		"ss":             scanner.NewSSScanner(),
		"ufw":            scanner.NewUFWScanner(),
		"sshd":           scanner.NewSSHDScanner(),
		"sysctl":         scanner.NewSysctlScanner(),
		"sudo":           scanner.NewSudoScanner(),
		"world-writable": scanner.NewWorldWritableScanner(),
	}

	order := []string{"docker", "ss", "ufw", "sshd", "sysctl", "sudo", "world-writable"}

	if only == "" {
		var out []scanner.Scanner
		for _, name := range order {
			out = append(out, all[name])
		}
		return out
	}

	if s, ok := all[only]; ok {
		return []scanner.Scanner{s}
	}

	fmt.Fprintf(os.Stderr, "unknown scanner: %q\n", only)
	os.Exit(1)
	return nil
}

func resolveProfilesPath() string {
	exe, err := os.Executable()
	if err == nil {
		p := filepath.Join(filepath.Dir(exe), "profiles.yaml")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "profiles.yaml"
}

func printHelp() {
	fmt.Printf(`secscore %s — local security analyzer

USAGE
  secscore [flags]

SCAN FLAGS
  --only <scanner>    Run a single scanner instead of all
                      Scanners: docker, ss, ufw, sshd, sysctl, sudo, world-writable
  --profiles <path>   Path to profiles.yaml (default: next to binary)
  --json              Output report as JSON (disables colors and progress)

FIX FLAGS  (require root)
  --fix               Interactively apply fixes for each finding
  --fix --auto        Apply all available fixes without prompting
  --fix --dry-run     Show what would be fixed without making changes

OTHER
  --version           Print version and exit
  --help              Show this help

EXIT CODES
  0   No issues found
  1   Warnings present
  2   Critical issues found

EXAMPLES
  sudo secscore                        # full scan
  sudo secscore --only sshd            # scan SSH config only
  sudo secscore --fix --dry-run        # preview available fixes
  sudo secscore --fix                  # interactive fix mode
  sudo secscore --fix --auto           # apply all fixes automatically
  secscore --json | jq '.Score'        # score only

INSTALL
  sudo make install                    # copies binary to /usr/local/bin
  go install github.com/casablanque-code/secscore/cmd/secscore@latest

`, version.Version)
}
