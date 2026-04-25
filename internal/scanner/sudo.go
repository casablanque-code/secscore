package scanner

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/casablanque-code/secscore/internal/model"
)

type SudoScanner struct{}

func NewSudoScanner() *SudoScanner { return &SudoScanner{} }

func (s *SudoScanner) Name() string { return "sudo" }

func (s *SudoScanner) Scan(snapshot *model.Snapshot) error {
	snapshot.Sudoers = parseSudoers()
	return nil
}

func parseSudoers() []model.SudoEntry {
	var entries []model.SudoEntry

	files := []string{"/etc/sudoers"}
	dropins, _ := filepath.Glob("/etc/sudoers.d/*")
	files = append(files, dropins...)

	for _, path := range files {
		entries = append(entries, parseSudoersFile(path)...)
	}
	return entries
}

func parseSudoersFile(path string) []model.SudoEntry {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var entries []model.SudoEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "@") {
			continue
		}
		if !strings.Contains(strings.ToUpper(line), "NOPASSWD") {
			continue
		}
		user := "unknown"
		if fields := strings.Fields(line); len(fields) > 0 {
			user = fields[0]
		}
		entries = append(entries, model.SudoEntry{
			User:   user,
			Source: path,
			Raw:    line,
		})
	}
	return entries
}
