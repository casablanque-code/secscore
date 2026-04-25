package engine

import (
	"testing"

	"secscore/internal/model"
)

func TestCalculateScore_NoPenalties(t *testing.T) {
	score := calculateScore(nil)
	if score != 100 {
		t.Errorf("empty findings: got %d want 100", score)
	}
}

func TestCalculateScore_Clamped(t *testing.T) {
	findings := []model.Finding{
		{Penalty: 60},
		{Penalty: 60},
	}
	score := calculateScore(findings)
	if score != 0 {
		t.Errorf("large penalties: got %d want 0", score)
	}
}

func TestCalculateScore_BonusCannotExceed100(t *testing.T) {
	findings := []model.Finding{
		{Penalty: -50}, // big bonus
	}
	score := calculateScore(findings)
	if score != 100 {
		t.Errorf("bonus beyond 100: got %d want 100", score)
	}
}

func TestCalculateScore_Mixed(t *testing.T) {
	findings := []model.Finding{
		{Penalty: 25}, // critical
		{Penalty: 10}, // warning
		{Penalty: -8}, // bonus
	}
	// 100 - 25 - 10 + 8 = 73
	score := calculateScore(findings)
	if score != 73 {
		t.Errorf("mixed penalties: got %d want 73", score)
	}
}

func TestDeduplicate(t *testing.T) {
	findings := []model.Finding{
		{ID: "a", Penalty: 10},
		{ID: "b", Penalty: 5},
		{ID: "a", Penalty: 10}, // duplicate
	}
	result := deduplicate(findings)
	if len(result) != 2 {
		t.Errorf("dedup: got %d want 2", len(result))
	}
}
