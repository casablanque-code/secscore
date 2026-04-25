package engine

import (
	"sort"

	"github.com/casablanque-code/secscore/internal/model"
	"github.com/casablanque-code/secscore/internal/rule"
	"github.com/casablanque-code/secscore/internal/scanner"
)

// ProgressFunc is called before each scanner runs. Used for live progress output.
type ProgressFunc func(scannerName string)

type Engine struct {
	scanners []scanner.Scanner
	rules    []rule.Rule
	progress ProgressFunc
}

func New(scanners []scanner.Scanner, rules []rule.Rule) *Engine {
	return &Engine{scanners: scanners, rules: rules}
}

// WithProgress sets a callback that is called before each scanner runs.
func (e *Engine) WithProgress(fn ProgressFunc) *Engine {
	e.progress = fn
	return e
}

func (e *Engine) Run(isRoot bool) (model.Report, error) {
	snapshot := model.Snapshot{
		IsRoot:    isRoot,
		UFWStatus: model.UFWUnknown,
	}

	for _, s := range e.scanners {
		if e.progress != nil {
			e.progress(s.Name())
		}
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
