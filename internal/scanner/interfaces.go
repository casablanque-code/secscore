package scanner

import "secscore/internal/model"

type Scanner interface {
	Name() string
	Scan(snapshot *model.Snapshot) error
}
