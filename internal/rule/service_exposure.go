package rule

import (
	"fmt"

	"secscore/internal/model"
)

type ServiceExposureRule struct{}

func NewServiceExposureRule() *ServiceExposureRule { return &ServiceExposureRule{} }
func (r *ServiceExposureRule) Name() string        { return "service-exposure" }

func (r *ServiceExposureRule) Evaluate(snapshot model.Snapshot) []model.Finding {
	var findings []model.Finding

	// Detect if any proxy container is running — used for context in descriptions
	proxyRunning := false
	for _, svc := range snapshot.Services {
		if model.IsProxyContainer(svc.Name, svc.Image) {
			proxyRunning = true
			break
		}
	}

	for _, svc := range snapshot.Services {
		// Proxy containers themselves publishing ports is expected — skip
		if model.IsProxyContainer(svc.Name, svc.Image) {
			findings = append(findings, model.Finding{
				ID:             fmt.Sprintf("proxy-public-%s-%d", svc.Name, svc.Port),
				Severity:       model.SeverityInfo,
				Title:          fmt.Sprintf("%s (proxy) is published on %s:%d", svc.Name, svc.HostIP, svc.Port),
				Description:    "Reverse proxy container — public binding is expected.",
				Recommendation: "Ensure only intended ports (80/443) are published.",
				Penalty:        0,
			})
			continue
		}

		if !isPublicBinding(svc.HostIP) {
			continue
		}

		// Service is on public IP — check if it's declared behind a proxy
		behindProxy := model.IsBehindProxy(svc.Name, svc.Image)

		switch svc.Type {
		case model.ServiceTypeAdmin:
			if behindProxy {
				// Known to be behind proxy — downgrade to WARNING, smaller penalty
				findings = append(findings, model.Finding{
					ID:       fmt.Sprintf("exposed-admin-direct-%s-%d", svc.Name, svc.Port),
					Severity: model.SeverityWarning,
					Title:    fmt.Sprintf("%s binds directly on %s:%d (behind proxy)", svc.Name, svc.HostIP, svc.Port),
					Description: "Service is marked as behind_proxy in profiles, but still binds to a public interface. " +
						"Direct access is possible if firewall rules don't block the port.",
					Recommendation: "Bind to 127.0.0.1 instead of 0.0.0.0 — the proxy can still reach it via localhost.",
					Penalty:        10,
				})
			} else {
				proxyTip := ""
				if proxyRunning {
					proxyTip = " A proxy (e.g. tollgate) is running — consider routing through it."
				}
				findings = append(findings, model.Finding{
					ID:       fmt.Sprintf("exposed-admin-%s-%d", svc.Name, svc.Port),
					Severity: model.SeverityCritical,
					Title:    fmt.Sprintf("%s is exposed on %s:%d", svc.Name, svc.HostIP, svc.Port),
					Description: "Administrative service is directly reachable from the network." + proxyTip,
					Recommendation: "Bind to 127.0.0.1 and route through a reverse proxy with auth.",
					Penalty:        25,
				})
			}

		case model.ServiceTypeInfra:
			findings = append(findings, model.Finding{
				ID:       fmt.Sprintf("exposed-infra-%s-%d", svc.Name, svc.Port),
				Severity: model.SeverityWarning,
				Title:    fmt.Sprintf("%s is directly reachable on %s:%d", svc.Name, svc.HostIP, svc.Port),
				Description: "Infrastructure service (DB, cache, etc.) is publicly accessible.",
				Recommendation: "Restrict to 127.0.0.1 or a private Docker network.",
				Penalty:        15,
			})

		default:
			findings = append(findings, model.Finding{
				ID:       fmt.Sprintf("exposed-app-%s-%d", svc.Name, svc.Port),
				Severity: model.SeverityWarning,
				Title:    fmt.Sprintf("%s is published on %s:%d", svc.Name, svc.HostIP, svc.Port),
				Description: "Application service is publicly bound.",
				Recommendation: "Confirm exposure is intended, or route through a proxy.",
				Penalty:        10,
			})
		}
	}

	return findings
}
