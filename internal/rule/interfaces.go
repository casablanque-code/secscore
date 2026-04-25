package rule

import "secscore/internal/model"

type Rule interface {
Name() string
Evaluate(snapshot model.Snapshot) []model.Finding
}
