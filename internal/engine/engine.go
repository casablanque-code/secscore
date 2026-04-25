package engine

import (
	"sort"

	"secscore/internal/model"
	"secscore/internal/rule"
	"secscore/internal/scanner"
)

type Engine struct {
	scanners []scanner.Scanner
	rules    []rule.Rule
}

func New(scanners []scanner.Scanner, rules []rule.Rule) *Engine {
	return &Engine{scanners: scanners, rules: rules}
}

func (e *Engine) Run(isRoot bool) (model.Report, error) {
	snapshot := model.Snapshot{
		IsRoot:    isRoot,
		UFWStatus: model.UFWUnknown,
	}

	for _, s := range e.scanners {
		if err := s.Scan(&snapshot); err != nil {
			return model.Report{}, err
		}
	}

	var findings []model.Finding
	for _, r := range e.rules {
		findings = append(findings, r.Evaluate(snapshot)...)
	}

	findings = deduplicate(findings)
	sort.SliceStable(findings, func(i, j int) bool {
		return severityRank(findings[i].Severity) < severityRank(findings[j].Severity)
	})

	return model.Report{
		Score:    calculateScore(findings),
		Findings: findings,
	}, nil
}

// calculateScore: start at 100, apply all penalties (positive = bad, negative = bonus).
// Score is clamped to [0, 100].
// Bonuses can push score back up, but only to 100 maximum.
func calculateScore(findings []model.Finding) int {
	score := 100
	for _, f := range findings {
		score -= f.Penalty
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score
}

func severityRank(s model.Severity) int {
	switch s {
	case model.SeverityCritical:
		return 0
	case model.SeverityWarning:
		return 1
	default:
		return 2
	}
}

func deduplicate(findings []model.Finding) []model.Finding {
	seen := make(map[string]bool)
	var result []model.Finding
	for _, f := range findings {
		if !seen[f.ID] {
			seen[f.ID] = true
			result = append(result, f)
		}
	}
	return result
}
