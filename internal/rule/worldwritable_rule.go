package rule

import (
	"fmt"
	"strings"

	"github.com/casablanque-code/secscore/internal/model"
)

type WorldWritableRule struct{}

func NewWorldWritableRule() *WorldWritableRule { return &WorldWritableRule{} }
func (r *WorldWritableRule) Name() string      { return "world-writable" }

func (r *WorldWritableRule) Evaluate(snapshot model.Snapshot) []model.Finding {
	// nil means scanner skipped (e.g. WSL2 detection) — emit an info note
	if snapshot.WorldWritable == nil {
		return []model.Finding{{
			ID:             "world-writable-skipped",
			Severity:       model.SeverityInfo,
			Title:          "World-writable scan skipped (WSL2 detected)",
			Description:    "On WSL2, DrvFs reports all files as 0777 regardless of real permissions. Scan would produce only false positives.",
			Recommendation: "Run secscore on a native Linux host or real VPS for reliable results.",
			Penalty:        0,
		}}
	}

	var findings []model.Finding

	for _, f := range snapshot.WorldWritable {
		severity := model.SeverityWarning
		penalty := 10
		desc := fmt.Sprintf("File %s is writable by any user (mode %04o).", f.Path, f.Mode&0777)

		if f.IsDir {
			severity = model.SeverityCritical
			penalty = 20
			desc = fmt.Sprintf(
				"Directory %s is writable by any user (mode %04o). "+
					"An attacker can plant files here.",
				f.Path, f.Mode&0777,
			)
		}

		if isCriticalPath(f.Path) {
			severity = model.SeverityCritical
			penalty = 25
		}

		findings = append(findings, model.Finding{
			ID:             fmt.Sprintf("world-writable-%s", sanitizePath(f.Path)),
			Severity:       severity,
			Title:          fmt.Sprintf("World-writable: %s", f.Path),
			Description:    desc,
			Recommendation: fmt.Sprintf("chmod o-w %s", f.Path),
			Penalty:        penalty,
		})
	}

	return findings
}

func isCriticalPath(path string) bool {
	criticals := []string{
		"/etc/passwd", "/etc/shadow", "/etc/sudoers",
		"/etc/ssh/", "/etc/cron",
		"/usr/bin/", "/usr/sbin/", "/usr/local/bin/",
	}
	for _, c := range criticals {
		if strings.HasPrefix(path, c) {
			return true
		}
	}
	return false
}

func sanitizePath(path string) string {
	b := make([]byte, 0, len(path))
	for i := 0; i < len(path); i++ {
		c := path[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' {
			b = append(b, c)
		} else {
			b = append(b, '-')
		}
	}
	return string(b)
}
