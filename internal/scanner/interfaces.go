package scanner

import "github.com/casablanque-code/secscore/internal/model"

type Scanner interface {
	Name() string
	Scan(snapshot *model.Snapshot) error
}
