package scanner

import (
	"os"
	"path/filepath"
	"strings"

	"secscore/internal/model"
)

type WorldWritableScanner struct{}

func NewWorldWritableScanner() *WorldWritableScanner { return &WorldWritableScanner{} }
func (s *WorldWritableScanner) Name() string         { return "world-writable" }

var wwScanDirs = []string{
	"/etc",
	"/usr/local/bin",
	"/usr/local/sbin",
	"/usr/bin",
	"/usr/sbin",
	"/opt",
}

// wwSkipPaths are skipped entirely — virtual fs, by-design 0777, or known noise.
var wwSkipPaths = []string{
	"/proc",
	"/sys",
	"/dev",
	"/run",
	"/tmp",     // world-writable by design
	"/var/tmp", // same
	"/etc/alternatives", // update-alternatives creates 0777 symlinks by design
}

const wwMaxResults = 20

func (s *WorldWritableScanner) Scan(snapshot *model.Snapshot) error {
	// On WSL2, DrvFs reports all files as 0777 — results would be meaningless noise.
	if isWSL2() {
		snapshot.WorldWritable = nil
		return nil
	}
	snapshot.WorldWritable = findWorldWritable(wwScanDirs, wwSkipPaths, wwMaxResults)
	return nil
}

// findWorldWritable walks dirs and returns files/dirs with o+w permissions.
// skipPaths entries are skipped entirely (pass nil or empty to skip nothing — useful in tests).
func findWorldWritable(dirs []string, skipPaths []string, maxResults int) []model.WorldWritableFile {
	var found []model.WorldWritableFile

	for _, dir := range dirs {
		if _, err := os.Lstat(dir); err != nil {
			continue
		}

		_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if shouldSkipPath(path, skipPaths) {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}

			info, err := d.Info()
			if err != nil {
				return nil
			}

			// Skip symlinks — their 0777 mode is meaningless, target perms matter.
			linfo, err := os.Lstat(path)
			if err == nil && linfo.Mode()&os.ModeSymlink != 0 {
				return nil
			}

			if info.Mode()&0002 != 0 {
				found = append(found, model.WorldWritableFile{
					Path:  path,
					Mode:  uint32(info.Mode()),
					IsDir: info.IsDir(),
				})
				if len(found) >= maxResults {
					return filepath.SkipAll
				}
			}
			return nil
		})
	}

	return found
}

func shouldSkipPath(path string, skipPaths []string) bool {
	for _, skip := range skipPaths {
		if path == skip || strings.HasPrefix(path, skip+"/") {
			return true
		}
	}
	return false
}

// shouldSkipWW is the production version using wwSkipPaths — used directly in tests.
func shouldSkipWW(path string) bool {
	return shouldSkipPath(path, wwSkipPaths)
}

// isWSL2 checks /proc/version for WSL2 indicators.
func isWSL2() bool {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return false
	}
	lower := strings.ToLower(string(data))
	return strings.Contains(lower, "microsoft") || strings.Contains(lower, "wsl")
}
