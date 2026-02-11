package marketplace

import (
	"testing"
)

func sampleIndex() *Index {
	return &Index{
		Name: "test-registry",
		URL:  "https://registry.example.com",
		Skills: []SkillEntry{
			{Name: "file-organiser", Version: "1.0.0", Description: "Organise files by extension", Author: "aegisclaw", Badge: BadgeVerified, Rating: 4.8, Downloads: 1200, Tags: []string{"files", "utility"}},
			{Name: "code-runner", Version: "1.0.0", Description: "Run code snippets safely", Author: "aegisclaw", Badge: BadgeSigned, Rating: 4.5, Downloads: 800, Tags: []string{"code", "sandbox"}},
			{Name: "git-stats", Version: "1.0.0", Description: "Git repository statistics", Author: "community", Badge: BadgeCommunity, Rating: 3.9, Downloads: 350, Tags: []string{"git", "analytics"}},
			{Name: "web-search", Version: "2.0.0", Description: "Search the web safely", Author: "aegisclaw", Badge: BadgeVerified, Rating: 4.2, Downloads: 2100, Tags: []string{"web", "search"}},
		},
	}
}

func TestSearch_ByName(t *testing.T) {
	idx := sampleIndex()
	results := Search(idx, "git")
	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}
	if results[0].Name != "git-stats" {
		t.Errorf("expected git-stats, got %s", results[0].Name)
	}
}

func TestSearch_ByTag(t *testing.T) {
	idx := sampleIndex()
	results := Search(idx, "sandbox")
	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}
}

func TestSearch_ByDescription(t *testing.T) {
	idx := sampleIndex()
	results := Search(idx, "organise")
	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}
}

func TestSearch_Empty(t *testing.T) {
	idx := sampleIndex()
	results := Search(idx, "")
	if len(results) != 4 {
		t.Errorf("expected 4 results for empty query, got %d", len(results))
	}
}

func TestSortByRating(t *testing.T) {
	idx := sampleIndex()
	SortByRating(idx.Skills)
	if idx.Skills[0].Name != "file-organiser" {
		t.Errorf("expected file-organiser first, got %s", idx.Skills[0].Name)
	}
}

func TestSortByDownloads(t *testing.T) {
	idx := sampleIndex()
	SortByDownloads(idx.Skills)
	if idx.Skills[0].Name != "web-search" {
		t.Errorf("expected web-search first (2100 downloads), got %s", idx.Skills[0].Name)
	}
}

func TestCache_SaveLoad(t *testing.T) {
	dir := t.TempDir()
	cache := NewCache(dir)
	idx := sampleIndex()

	if err := cache.Save(idx); err != nil {
		t.Fatalf("save error: %v", err)
	}

	loaded, err := cache.Load()
	if err != nil {
		t.Fatalf("load error: %v", err)
	}

	if len(loaded.Skills) != 4 {
		t.Errorf("expected 4 skills, got %d", len(loaded.Skills))
	}
	if loaded.FetchedAt == "" {
		t.Error("expected fetched_at to be set")
	}
}

func TestBadgeIcon(t *testing.T) {
	if BadgeIcon(BadgeVerified) != "[V]" {
		t.Error("expected [V] for verified")
	}
	if BadgeIcon(BadgeSigned) != "[S]" {
		t.Error("expected [S] for signed")
	}
	if BadgeIcon(BadgeCommunity) != "[C]" {
		t.Error("expected [C] for community")
	}
}

func TestFormatEntry(t *testing.T) {
	e := SkillEntry{
		Name: "test-skill", Version: "1.0", Description: "A test", Badge: BadgeVerified, Rating: 4.5, Downloads: 100, Tags: []string{"test"},
	}
	s := FormatEntry(e)
	if s == "" {
		t.Error("expected non-empty formatted entry")
	}
}
