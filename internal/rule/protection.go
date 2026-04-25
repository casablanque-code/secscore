package rule

import (
	"fmt"

	"github.com/casablanque-code/secscore/internal/model"
)

// ProtectionRule gives positive score for services correctly bound to localhost.
// It does NOT penalize — it only rewards good practice.
type ProtectionRule struct{}

func NewProtectionRule() *ProtectionRule  { return &ProtectionRule{} }
func (r *ProtectionRule) Name() string    { return "protection" }

func (r *ProtectionRule) Evaluate(snapshot model.Snapshot) []model.Finding {
	var findings []model.Finding

	for _, svc := range snapshot.Services {
		if isPublicBinding(svc.HostIP) {
			continue
		}
		// Skip proxy containers — they're expected to be localhost
		if model.IsProxyContainer(svc.Name, svc.Image) {
			continue
		}
		findings = append(findings, model.Finding{
			ID:             fmt.Sprintf("protected-%s-%d", svc.Name, svc.Port),
			Severity:       model.SeverityInfo,
			Title:          fmt.Sprintf("%s is restricted to localhost", svc.Name),
			Description:    "Service is not directly reachable from the network.",
			Recommendation: "No action needed.",
			Penalty:        -2,
		})
	}

	return findings
}
