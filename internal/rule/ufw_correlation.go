package rule

import (
	"fmt"
	"strings"

	"github.com/casablanque-code/secscore/internal/model"
)

// UFWCorrelationRule correlates ss listeners with ufw rules.
//
// Intention-based semantics:
//
//   Port open + ALLOW rule  → INFO, no penalty  (user knows, intentional)
//   Port open + LIMIT rule  → INFO, bonus        (good practice)
//   Port open + DENY rule   → CRITICAL anomaly   (firewall blocks but port is open — Docker bypass?)
//   Port open + no rule     → WARNING            (unknown intention)
//   ufw inactive            → CRITICAL
//   ufw unknown             → WARNING

type UFWCorrelationRule struct{}

func NewUFWCorrelationRule() *UFWCorrelationRule { return &UFWCorrelationRule{} }
func (r *UFWCorrelationRule) Name() string       { return "ufw-correlation" }

func (r *UFWCorrelationRule) Evaluate(snapshot model.Snapshot) []model.Finding {
	var findings []model.Finding

	switch snapshot.UFWStatus {
	case model.UFWUnknown:
		findings = append(findings, model.Finding{
			ID:             "ufw-not-found",
			Severity:       model.SeverityWarning,
			Title:          "ufw not found or status unknown",
			Description:    "Could not determine firewall status.",
			Recommendation: "Install and configure ufw: apt install ufw && ufw enable",
			Penalty:        15,
		})
		return findings

	case model.UFWInactive:
		findings = append(findings, model.Finding{
			ID:             "ufw-inactive",
			Severity:       model.SeverityCritical,
			Title:          "ufw is installed but inactive",
			Description:    "Host firewall is disabled. All ports are accessible from the network.",
			Recommendation: "Run: ufw enable (ensure SSH rule exists first to avoid lockout)",
			Penalty:        25,
			Fix: &model.Fix{
				Description: "Enable ufw firewall",
				Actions: []model.Action{
					{Kind: model.ActionCommand, Cmd: []string{"ufw", "--force", "enable"}},
				},
			},
		})
		return findings
	}

	// ufw is active
	coveredCount := 0
	totalPublic := 0

	for _, l := range snapshot.HostListeners {
		if isLocalOnlyAddress(l.Address) {
			continue
		}
		if l.Port == 0 {
			continue
		}

		totalPublic++
		proto := normalizeProto(l.Proto)
		matched := ufwRuleForPort(snapshot.UFWRules, l.Port, proto)

		processStr := ""
		if l.Process != "" {
			processStr = fmt.Sprintf(" [%s]", l.Process)
		}

		switch {
		case matched == nil:
			findings = append(findings, model.Finding{
				ID:       fmt.Sprintf("ufw-no-rule-%d-%s", l.Port, proto),
				Severity: model.SeverityWarning,
				Title:    fmt.Sprintf("Port %d/%s has no ufw rule%s", l.Port, proto, processStr),
				Description: fmt.Sprintf(
					"Port %d is open on %s with no ufw rule. "+
						"Add any rule to express your intention explicitly.",
					l.Port, l.Address,
				),
				Recommendation: fmt.Sprintf(
					"Allow: ufw allow %d/%s  |  Rate-limit: ufw limit %d/%s  |  Block: ufw deny %d/%s",
					l.Port, proto, l.Port, proto, l.Port, proto,
				),
				Penalty: 8,
				Fix: &model.Fix{
					Description: fmt.Sprintf("Add ufw allow rule for port %d/%s", l.Port, proto),
					Actions: []model.Action{
						{
							Kind: model.ActionCommand,
							Cmd:  []string{"ufw", "allow", fmt.Sprintf("%d/%s", l.Port, proto)},
						},
					},
				},
			})

		case matched.Action == "DENY" || matched.Action == "REJECT":
			// Anomaly: firewall blocks it, but port is actually open
			findings = append(findings, model.Finding{
				ID:       fmt.Sprintf("ufw-denied-but-open-%d-%s", l.Port, proto),
				Severity: model.SeverityCritical,
				Title:    fmt.Sprintf("Port %d/%s open despite ufw %s%s", l.Port, proto, matched.Action, processStr),
				Description: fmt.Sprintf(
					"ufw has a %s rule for port %d, but the port is actively listening. "+
						"Docker may be inserting iptables rules that bypass ufw.",
					matched.Action, l.Port,
				),
				Recommendation: "Bind the container to 127.0.0.1 in docker-compose (\"127.0.0.1:PORT:PORT\") " +
					"so Docker doesn't open the port externally.",
				Penalty: 20,
			})
			coveredCount++ // still covered, just anomalous

		case matched.Action == "LIMIT":
			coveredCount++
			findings = append(findings, model.Finding{
				ID:       fmt.Sprintf("ufw-limited-%d-%s", l.Port, proto),
				Severity: model.SeverityInfo,
				Title:    fmt.Sprintf("Port %d/%s is open and rate-limited%s", l.Port, proto, processStr),
				Description: fmt.Sprintf("ufw LIMIT active on port %d — brute-force protection enabled.", l.Port),
				Recommendation: "No action needed.",
				Penalty:        -3,
			})

		case matched.Action == "ALLOW":
			coveredCount++
			findings = append(findings, model.Finding{
				ID:       fmt.Sprintf("ufw-allowed-%d-%s", l.Port, proto),
				Severity: model.SeverityInfo,
				Title:    fmt.Sprintf("Port %d/%s explicitly allowed%s", l.Port, proto, processStr),
				Description: fmt.Sprintf("ufw ALLOW rule for port %d — exposure is intentional.", l.Port),
				Recommendation: "No action needed.",
				Penalty:        0,
			})
		}
	}

	// Bonus: every public port has an explicit rule
	if totalPublic > 0 && coveredCount == totalPublic {
		findings = append(findings, model.Finding{
			ID:             "ufw-fully-covered",
			Severity:       model.SeverityInfo,
			Title:          "All open ports have explicit ufw rules",
			Description:    "Every public-facing listener is covered by an intentional ufw rule.",
			Recommendation: "No action needed.",
			Penalty:        -10,
		})
	}

	return findings
}

func ufwRuleForPort(rules []model.UFWRule, port int, proto string) *model.UFWRule {
	for i := range rules {
		r := &rules[i]
		if r.Port != 0 && r.Port != port {
			continue
		}
		if r.Proto != "any" && r.Proto != proto {
			continue
		}
		return r
	}
	return nil
}

func normalizeProto(proto string) string {
	if strings.ToLower(proto) == "udp" {
		return "udp"
	}
	return "tcp"
}

func isLocalOnlyAddress(addr string) bool {
	return strings.HasPrefix(addr, "127.") ||
		strings.HasPrefix(addr, "[::1]") ||
		strings.HasPrefix(addr, "::1")
}
