package rule

import "github.com/casablanque-code/secscore/internal/model"

type Rule interface {
Name() string
Evaluate(snapshot model.Snapshot) []model.Finding
}
