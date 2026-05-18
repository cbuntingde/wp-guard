package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewBaseline(t *testing.T) {
	root := "/test/path"
	baseline := NewBaseline(root)

	if baseline == nil {
		t.Fatal("NewBaseline returned nil")
	}
	if baseline.Root != root {
		t.Errorf("expected root=%s, got %s", root, baseline.Root)
	}
	if baseline.Version != 1 {
		t.Errorf("expected version=1, got %d", baseline.Version)
	}
	if len(baseline.Files) != 0 {
		t.Errorf("expected empty files map, got %d", len(baseline.Files))
	}
}

func TestHashFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")

	content := "test content"
	if err := os.WriteFile(testFile, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	hash, err := HashFile(testFile)
	if err != nil {
		t.Fatalf("HashFile failed: %v", err)
	}

	if hash == "" {
		t.Error("expected non-empty hash")
	}

	// Verify hash is consistent
	hash2, err := HashFile(testFile)
	if err != nil {
		t.Fatalf("second HashFile failed: %v", err)
	}

	if hash != hash2 {
		t.Error("hash should be consistent for same file")
	}
}

func TestHashFileDifferentContent(t *testing.T) {
	tmpDir := t.TempDir()

	file1 := filepath.Join(tmpDir, "file1.txt")
	file2 := filepath.Join(tmpDir, "file2.txt")

	if err := os.WriteFile(file1, []byte("content1"), 0600); err != nil {
		t.Fatalf("failed to write file1: %v", err)
	}
	if err := os.WriteFile(file2, []byte("content2"), 0600); err != nil {
		t.Fatalf("failed to write file2: %v", err)
	}

	hash1, err := HashFile(file1)
	if err != nil {
		t.Fatalf("HashFile(file1) failed: %v", err)
	}

	hash2, err := HashFile(file2)
	if err != nil {
		t.Fatalf("HashFile(file2) failed: %v", err)
	}

	if hash1 == hash2 {
		t.Error("different files should have different hashes")
	}
}

func TestScanDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test files
	phpFiles := []string{"index.php", "test.php"}
	for _, name := range phpFiles {
		path := filepath.Join(tmpDir, name)
		if err := os.WriteFile(path, []byte("<?php echo 'test'; ?>"), 0600); err != nil {
			t.Fatalf("failed to write %s: %v", name, err)
		}
	}

	// Create a non-php file (should be included by ScanDirectory)
	configFile := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(configFile, []byte("{}"), 0600); err != nil {
		t.Fatalf("failed to write config.json: %v", err)
	}

	baseline, err := ScanDirectory(tmpDir, []string{}, []string{})
	if err != nil {
		t.Fatalf("ScanDirectory failed: %v", err)
	}

	if baseline == nil {
		t.Fatal("ScanDirectory returned nil")
	}

	// Should find all 3 files
	if len(baseline.Files) != 3 {
		t.Errorf("expected 3 files, got %d", len(baseline.Files))
	}

	for _, name := range phpFiles {
		if _, ok := baseline.Files[name]; !ok {
			t.Errorf("expected to find %s in baseline", name)
		}
	}
}

func TestScanDirectoryWithExclusions(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test files
	if err := os.WriteFile(filepath.Join(tmpDir, "test.php"), []byte("php"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "test.txt"), []byte("text"), 0600); err != nil {
		t.Fatal(err)
	}

	// Exclude .txt files
	baseline, err := ScanDirectory(tmpDir, []string{".txt"}, []string{})
	if err != nil {
		t.Fatalf("ScanDirectory failed: %v", err)
	}

	if len(baseline.Files) != 1 {
		t.Errorf("expected 1 file after excluding .txt, got %d", len(baseline.Files))
	}

	if _, ok := baseline.Files["test.php"]; !ok {
		t.Error("expected test.php to be in baseline")
	}
	if _, ok := baseline.Files["test.txt"]; ok {
		t.Error("test.txt should be excluded")
	}
}

func TestBaselineSaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	baselineFile := filepath.Join(tmpDir, "baseline.json")

	// Create a baseline
	baseline := NewBaseline("/test/root")
	baseline.Files["test.php"] = FileRecord{
		Path:    "test.php",
		Hash:    "abc123",
		Size:    100,
		ModTime: time.Now(),
		Mode:    "-rw-r--r--",
	}

	// Save it
	if err := baseline.Save(baselineFile); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(baselineFile); err != nil {
		t.Fatalf("baseline file not created: %v", err)
	}

	// Load it back
	loaded, err := LoadBaseline(baselineFile)
	if err != nil {
		t.Fatalf("LoadBaseline failed: %v", err)
	}

	if loaded == nil {
		t.Fatal("LoadBaseline returned nil")
	}
	if loaded.Root != baseline.Root {
		t.Errorf("expected root=%s, got %s", baseline.Root, loaded.Root)
	}
	if len(loaded.Files) != 1 {
		t.Errorf("expected 1 file, got %d", len(loaded.Files))
	}

	record, ok := loaded.Files["test.php"]
	if !ok {
		t.Error("expected test.php in loaded baseline")
	}
	if record.Hash != "abc123" {
		t.Errorf("expected hash=abc123, got %s", record.Hash)
	}
}

func TestCheckFileClean(t *testing.T) {
	baseline := NewBaseline("/test")
	baseline.Files["unchanged.php"] = FileRecord{
		Path: "unchanged.php",
		Hash: "abc123",
	}

	changeType := baseline.CheckFile("unchanged.php", "abc123", 100)
	if changeType != ChangeClean {
		t.Errorf("expected ChangeClean, got %v", changeType)
	}
}

func TestCheckFileModified(t *testing.T) {
	baseline := NewBaseline("/test")
	baseline.Files["modified.php"] = FileRecord{
		Path: "modified.php",
		Hash: "abc123",
	}

	changeType := baseline.CheckFile("modified.php", "def456", 100)
	if changeType != ChangeModified {
		t.Errorf("expected ChangeModified, got %v", changeType)
	}
}

func TestCheckFileNew(t *testing.T) {
	baseline := NewBaseline("/test")

	changeType := baseline.CheckFile("newfile.php", "abc123", 100)
	if changeType != ChangeNew {
		t.Errorf("expected ChangeNew, got %v", changeType)
	}
}

func TestFileRecordFields(t *testing.T) {
	record := FileRecord{
		Path:       "test.php",
		Hash:       "abc123",
		Size:       1024,
		Mode:       "-rw-r--r--",
		IsNew:      true,
		IsDeleted:  false,
		WasQuarantined: true,
	}

	if record.Path != "test.php" {
		t.Errorf("expected path=test.php, got %s", record.Path)
	}
	if record.IsNew != true {
		t.Error("expected IsNew=true")
	}
	if record.WasQuarantined != true {
		t.Error("expected WasQuarantined=true")
	}
}
