package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/casablanque-code/secscore/internal/engine"
	"github.com/casablanque-code/secscore/internal/model"
	"github.com/casablanque-code/secscore/internal/printer"
	"github.com/casablanque-code/secscore/internal/rule"
	"github.com/casablanque-code/secscore/internal/scanner"
	"github.com/casablanque-code/secscore/internal/version"
)

func main() {
	var jsonOutput bool
	var only string
	var showVersion bool
	var profilesPath string

	flag.BoolVar(&jsonOutput, "json", false, "output in JSON format")
	flag.StringVar(&only, "only", "", "run only specific scanner: docker, ss, ufw, sshd, sysctl, sudo, world-writable")
	flag.StringVar(&profilesPath, "profiles", "", "path to profiles.yaml (default: next to binary)")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Printf("secscore %s\n", version.Version)
		return
	}

	isRoot := os.Geteuid() == 0
	if !isRoot && !jsonOutput {
		fmt.Fprintln(os.Stderr, "⚠  Running without root. ss process info, sudo and sysctl reads may be incomplete.")
		fmt.Fprintln(os.Stderr, "   Run with sudo for full results.")
		fmt.Fprintln(os.Stderr)
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

	// Show live progress on terminal, skip for JSON output
	if !jsonOutput {
		eng.WithProgress(func(name string) {
			printer.PrintProgress(os.Stderr, name)
		})
	}

	report, err := eng.Run(isRoot)
	if err != nil {
		printer.PrintProgressDone(os.Stderr)
		fmt.Fprintf(os.Stderr, "secscore: %v\n", err)
		os.Exit(1)
	}

	printer.PrintProgressDone(os.Stderr)

	if jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(report)
		return
	}

	printer.PrintReport(os.Stdout, report)

	if report.HasCritical() {
		os.Exit(2)
	}
	if report.HasWarning() {
		os.Exit(1)
	}
}

func buildScanners(only string) []scanner.Scanner {
	all := map[string]scanner.Scanner{
		"docker":        scanner.NewDockerScanner(),
		"ss":            scanner.NewSSScanner(),
		"ufw":           scanner.NewUFWScanner(),
		"sshd":          scanner.NewSSHDScanner(),
		"sysctl":        scanner.NewSysctlScanner(),
		"sudo":          scanner.NewSudoScanner(),
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
