package fixer

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/casablanque-code/secscore/internal/model"
)

// Result holds the outcome of applying a single Action.
type Result struct {
	Action  model.Action
	Applied bool
	Err     error
	Detail  string // human-readable description of what was done
}

// Apply executes all actions for a fix. If dryRun is true, nothing is changed.
func Apply(fix *model.Fix, dryRun bool) []Result {
	var results []Result
	for _, action := range fix.Actions {
		r := applyAction(action, dryRun)
		results = append(results, r)
	}
	return results
}

func applyAction(a model.Action, dryRun bool) Result {
	switch a.Kind {
	case model.ActionFileEdit:
		return applyFileEdit(a, dryRun)
	case model.ActionSysctlSet:
		return applySysctlSet(a, dryRun)
	case model.ActionCommand:
		return applyCommand(a, dryRun)
	default:
		return Result{Action: a, Err: fmt.Errorf("unknown action kind: %s", a.Kind)}
	}
}

// applyFileEdit finds Search in File and replaces the whole line with Replace.
// If Search is not found, Append is added at the end of the file.
func applyFileEdit(a model.Action, dryRun bool) Result {
	r := Result{Action: a}

	content, err := os.ReadFile(a.File)
	if err != nil {
		r.Err = fmt.Errorf("read %s: %w", a.File, err)
		return r
	}

	lines := strings.Split(string(content), "\n")
	found := false
	var newLines []string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Match: line contains Search (case-insensitive key match)
		if strings.Contains(strings.ToLower(trimmed), strings.ToLower(a.Search)) &&
			!strings.HasPrefix(trimmed, "#") {
			newLines = append(newLines, a.Replace)
			found = true
		} else {
			newLines = append(newLines, line)
		}
	}

	if !found {
		if a.Append != "" {
			newLines = append(newLines, a.Append)
			r.Detail = fmt.Sprintf("appended %q to %s", a.Append, a.File)
		} else {
			r.Detail = fmt.Sprintf("no matching line found in %s", a.File)
			r.Applied = true
			return r
		}
	} else {
		r.Detail = fmt.Sprintf("replaced line matching %q in %s", a.Search, a.File)
	}

	if dryRun {
		r.Applied = false
		return r
	}

	// Write atomically: write to temp, rename
	tmp, err := os.CreateTemp("", "secscore-edit-*")
	if err != nil {
		r.Err = fmt.Errorf("create temp file: %w", err)
		return r
	}
	tmpName := tmp.Name()

	_, err = io.WriteString(tmp, strings.Join(newLines, "\n"))
	tmp.Close()
	if err != nil {
		os.Remove(tmpName)
		r.Err = fmt.Errorf("write temp file: %w", err)
		return r
	}

	// Preserve original file permissions
	info, err := os.Stat(a.File)
	if err == nil {
		os.Chmod(tmpName, info.Mode())
	}

	if err := os.Rename(tmpName, a.File); err != nil {
		os.Remove(tmpName)
		r.Err = fmt.Errorf("rename to %s: %w", a.File, err)
		return r
	}

	r.Applied = true
	return r
}

func applySysctlSet(a model.Action, dryRun bool) Result {
	r := Result{Action: a}
	r.Detail = fmt.Sprintf("sysctl %s=%s", a.Key, a.Value)

	if dryRun {
		return r
	}

	// Apply immediately
	if err := exec.Command("sysctl", "-w", fmt.Sprintf("%s=%s", a.Key, a.Value)).Run(); err != nil {
		r.Err = fmt.Errorf("sysctl -w %s=%s: %w", a.Key, a.Value, err)
		return r
	}

	// Persist to sysctl.d
	persistFile := "/etc/sysctl.d/99-secscore.conf"
	if err := persistSysctl(persistFile, a.Key, a.Value); err != nil {
		r.Err = fmt.Errorf("persist sysctl: %w", err)
		return r
	}

	r.Applied = true
	r.Detail = fmt.Sprintf("set %s=%s (applied + persisted to %s)", a.Key, a.Value, persistFile)
	return r
}

func persistSysctl(file, key, value string) error {
	// Read existing file if present
	var lines []string
	if f, err := os.Open(file); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			// Skip existing entry for this key
			if !strings.HasPrefix(strings.TrimSpace(line), key) {
				lines = append(lines, line)
			}
		}
		f.Close()
	}

	lines = append(lines, fmt.Sprintf("%s=%s", key, value))

	return os.WriteFile(file, []byte(strings.Join(lines, "\n")+"\n"), 0644)
}

func applyCommand(a model.Action, dryRun bool) Result {
	r := Result{Action: a}
	r.Detail = strings.Join(a.Cmd, " ")

	if len(a.Cmd) == 0 {
		r.Err = fmt.Errorf("empty command")
		return r
	}

	if dryRun {
		return r
	}

	cmd := exec.Command(a.Cmd[0], a.Cmd[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.Err = fmt.Errorf("%s: %w\n%s", strings.Join(a.Cmd, " "), err, strings.TrimSpace(string(out)))
		return r
	}

	r.Applied = true
	return r
}
