package rule

import (
	"testing"

	"github.com/casablanque-code/secscore/internal/model"
)

func TestSysctlRule_ASLRDisabled_Critical(t *testing.T) {
	snap := model.Snapshot{
		Sysctl: model.SysctlValues{
			Available: true,
			Params:    map[string]string{"kernel.randomize_va_space": "0"},
		},
	}
	findings := NewSysctlRule().Evaluate(snap)
	assertFinding(t, findings, "sysctl-kernel.randomize_va_space", model.SeverityCritical)
}

func TestSysctlRule_GoodValues_NoFindings(t *testing.T) {
	snap := model.Snapshot{
		Sysctl: model.SysctlValues{
			Available: true,
			Params: map[string]string{
				"kernel.randomize_va_space":           "2",
				"net.ipv4.tcp_syncookies":             "1",
				"kernel.dmesg_restrict":               "1",
				"net.ipv4.conf.all.accept_redirects":  "0",
				"fs.suid_dumpable":                    "0",
			},
		},
	}
	findings := NewSysctlRule().Evaluate(snap)
	for _, f := range findings {
		if f.Severity == model.SeverityCritical || f.Severity == model.SeverityWarning {
			t.Errorf("unexpected finding for good sysctl values: %s %s", f.Severity, f.ID)
		}
	}
}

func TestSysctlRule_SyncookiesOff_Warning(t *testing.T) {
	snap := model.Snapshot{
		Sysctl: model.SysctlValues{
			Available: true,
			Params:    map[string]string{"net.ipv4.tcp_syncookies": "0"},
		},
	}
	findings := NewSysctlRule().Evaluate(snap)
	assertFinding(t, findings, "sysctl-net.ipv4.tcp_syncookies", model.SeverityWarning)
}

func TestSysctlRule_Unavailable_NoFindings(t *testing.T) {
	snap := model.Snapshot{
		Sysctl: model.SysctlValues{Available: false},
	}
	findings := NewSysctlRule().Evaluate(snap)
	if len(findings) != 0 {
		t.Errorf("expected no findings when sysctl unavailable, got %d", len(findings))
	}
}
