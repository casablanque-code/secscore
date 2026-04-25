package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// skipIfWSL2 skips the test on WSL2 where chmod o+w is not reliably supported.
func skipIfWSL2(t *testing.T) {
	t.Helper()
	if isWSL2() {
		t.Skip("skipping on WSL2: filesystem does not reliably support o+w permissions")
	}
}

func TestWorldWritable_DetectsOtherWrite(t *testing.T) {
	skipIfWSL2(t)

	dir := t.TempDir()

	ww := filepath.Join(dir, "dangerous.sh")
	if err := os.WriteFile(ww, []byte("#!/bin/bash\n"), 0777); err != nil {
		t.Fatal(err)
	}
	normal := filepath.Join(dir, "normal.sh")
	if err := os.WriteFile(normal, []byte("#!/bin/bash\n"), 0755); err != nil {
		t.Fatal(err)
	}

	found := findWorldWritable([]string{dir}, nil, 20)

	if len(found) != 1 {
		t.Fatalf("expected 1 world-writable file, got %d: %+v", len(found), found)
	}
	if found[0].Path != ww {
		t.Errorf("wrong path: got %q want %q", found[0].Path, ww)
	}
	if found[0].IsDir {
		t.Error("expected IsDir=false for file")
	}
}

func TestWorldWritable_SkipsSymlinks(t *testing.T) {
	skipIfWSL2(t)

	dir := t.TempDir()

	real := filepath.Join(dir, "real.sh")
	if err := os.WriteFile(real, []byte("x"), 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.sh")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	found := findWorldWritable([]string{dir}, nil, 20)

	for _, f := range found {
		if f.Path == link {
			t.Errorf("symlink %q should be skipped", link)
		}
	}
}

func TestWorldWritable_SkipsAlternatives(t *testing.T) {
	// shouldSkipWW uses wwSkipPaths — no filesystem access, runs on any platform
	cases := []struct {
		path string
		want bool
	}{
		{"/etc/alternatives", true},
		{"/etc/alternatives/awk", true},
		{"/etc/alternatives/editor.1.gz", true},
		{"/etc/ssh/sshd_config", false},
		{"/usr/local/bin/mytool", false},
		{"/tmp/something", true},
		{"/var/tmp/something", true},
		{"/proc/version", true},
	}

	for _, c := range cases {
		got := shouldSkipWW(c.path)
		if got != c.want {
			t.Errorf("shouldSkipWW(%q): got %v want %v", c.path, got, c.want)
		}
	}
}

func TestWorldWritable_NormalPerms_NoFindings(t *testing.T) {
	skipIfWSL2(t)

	dir := t.TempDir()

	for _, f := range []struct {
		name string
		mode os.FileMode
	}{
		{"exec.sh", 0755},
		{"config.conf", 0644},
		{"private.key", 0600},
	} {
		if err := os.WriteFile(filepath.Join(dir, f.name), []byte("x"), f.mode); err != nil {
			t.Fatal(err)
		}
	}

	found := findWorldWritable([]string{dir}, nil, 20)
	if len(found) != 0 {
		t.Errorf("expected 0 findings, got %d: %+v", len(found), found)
	}
}

func TestWorldWritable_MaxResultsCap(t *testing.T) {
	skipIfWSL2(t)

	dir := t.TempDir()

	for i := 0; i < 30; i++ {
		name := filepath.Join(dir, fmt.Sprintf("file%d.sh", i))
		_ = os.WriteFile(name, []byte("x"), 0777)
	}

	found := findWorldWritable([]string{dir}, nil, 5)
	if len(found) > 5 {
		t.Errorf("expected at most 5 results, got %d", len(found))
	}
}
