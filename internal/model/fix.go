package model

// Fix describes an automated remediation for a Finding.
// Not all findings are fixable — Fix is nil when no safe automation exists.
type Fix struct {
	Description string   // human-readable summary shown in --fix mode
	Actions     []Action // ordered steps to apply
}

type ActionKind string

const (
	// ActionFileEdit finds a line matching Search in File and replaces it.
	// If no matching line exists, Append is added at end of file.
	ActionFileEdit ActionKind = "file_edit"

	// ActionSysctlSet writes Key=Value to /etc/sysctl.d/99-secscore.conf
	// and applies it immediately via sysctl -w.
	ActionSysctlSet ActionKind = "sysctl_set"

	// ActionCommand runs an arbitrary command (args[0] is binary, rest are args).
	ActionCommand ActionKind = "command"
)

type Action struct {
	Kind ActionKind

	// ActionFileEdit
	File    string // absolute path
	Search  string // exact substring to find in a line (first match wins)
	Replace string // replacement line (full line, no newline needed)
	Append  string // line to append if Search not found

	// ActionSysctlSet
	Key   string
	Value string

	// ActionCommand
	Cmd []string // e.g. ["systemctl", "reload", "sshd"]
}
