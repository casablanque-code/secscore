package rule

import (
"fmt"
"net/http"
"time"

"secscore/internal/model"
)

type HTTPAuthRule struct{}

func NewHTTPAuthRule() *HTTPAuthRule {
return &HTTPAuthRule{}
}

func (r *HTTPAuthRule) Name() string {
return "http-auth"
}

func (r *HTTPAuthRule) Evaluate(snapshot model.Snapshot) []model.Finding {
var findings []model.Finding

client := &http.Client{
Timeout: 2 * time.Second,
}

for _, svc := range snapshot.Services {
// проверяем только HTTP-порты
if svc.ContainerPort != 80 && svc.ContainerPort != 443 &&
   svc.ContainerPort != 3000 && svc.ContainerPort != 8080 &&
   svc.ContainerPort != 9000 && svc.ContainerPort != 5678 {
    continue
}

if svc.Type != model.ServiceTypeAdmin || !svc.HTTP || !isPublicBinding(svc.HostIP) {
	continue
}

if svc.Port == 0 {
continue
}

urls := []string{
fmt.Sprintf("http://localhost:%d/api", svc.Port),
fmt.Sprintf("http://localhost:%d/login", svc.Port),
fmt.Sprintf("http://localhost:%d", svc.Port),
}

isProtected := false

for _, url := range urls {
resp, err := client.Get(url)
if err != nil {
continue
}

status := resp.StatusCode
resp.Body.Close()

if status == 401 || status == 403 {
isProtected = true
break
}
}

if isProtected {
continue
}

findings = append(findings, model.Finding{
ID:       fmt.Sprintf("no-auth-%s-%d", svc.Name, svc.Port),
Severity: model.SeverityWarning,
Title:    fmt.Sprintf("%s may be accessible without auth", svc.Name),
Description: "Service did not require authentication on common endpoints",
Recommendation: "Bind service to 127.0.0.1 and expose via reverse proxy with auth.",
Penalty: 10,
})
}

return findings
}
