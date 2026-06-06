// Package marketplace provides a skill marketplace with ratings, security badges,
// and local index caching for discovering and managing AegisClaw skills.
package marketplace

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// SecurityBadge indicates the security verification level of a skill.
type SecurityBadge string

const (
	BadgeVerified   SecurityBadge = "verified"   // Signed + reviewed
	BadgeSigned     SecurityBadge = "signed"     // Has valid signature
	BadgeCommunity  SecurityBadge = "community"  // No verification
)

// SkillEntry is a marketplace listing for a skill.
type SkillEntry struct {
	Name        string        `json:"name"`
	Version     string        `json:"version"`
	Description string        `json:"description"`
	Author      string        `json:"author"`
	Badge       SecurityBadge `json:"badge"`
	Rating      float64       `json:"rating"`       // 0.0 – 5.0
	Downloads   int           `json:"downloads"`
	Tags        []string      `json:"tags,omitempty"`
	ManifestURL string        `json:"manifest_url"`
	UpdatedAt   string        `json:"updated_at"`
}

// Index is the full marketplace index.
type Index struct {
	Name      string       `json:"name"`
	URL       string       `json:"url"`
	Skills    []SkillEntry `json:"skills"`
	FetchedAt string       `json:"fetched_at"`
}

// Cache manages a local cache of the marketplace index.
type Cache struct {
	dir string
}

// NewCache creates a marketplace cache in the given directory.
func NewCache(dir string) *Cache {
	return &Cache{dir: dir}
}

// Save writes the index to disk.
func (c *Cache) Save(idx *Index) error {
	if err := os.MkdirAll(c.dir, 0700); err != nil {
		return err
	}
	idx.FetchedAt = time.Now().UTC().Format(time.RFC3339)
	data, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(c.dir, "marketplace.json"), data, 0600)
}

// Load reads the cached index from disk.
func (c *Cache) Load() (*Index, error) {
	data, err := os.ReadFile(filepath.Join(c.dir, "marketplace.json"))
	if err != nil {
		return nil, err
	}
	var idx Index
	if err := json.Unmarshal(data, &idx); err != nil {
		return nil, err
	}
	return &idx, nil
}

// Search filters skills by query string matching name, description, or tags.
func Search(idx *Index, query string) []SkillEntry {
	if query == "" {
		return idx.Skills
	}
	q := strings.ToLower(query)
	var results []SkillEntry
	for _, s := range idx.Skills {
		if strings.Contains(strings.ToLower(s.Name), q) ||
			strings.Contains(strings.ToLower(s.Description), q) ||
			matchTags(s.Tags, q) {
			results = append(results, s)
		}
	}
	return results
}

// SortByRating sorts entries by rating descending.
func SortByRating(entries []SkillEntry) {
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Rating > entries[j].Rating
	})
}

// SortByDownloads sorts entries by download count descending.
func SortByDownloads(entries []SkillEntry) {
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Downloads > entries[j].Downloads
	})
}

// BadgeIcon returns a display character for the badge type.
func BadgeIcon(b SecurityBadge) string {
	switch b {
	case BadgeVerified:
		return "[V]"
	case BadgeSigned:
		return "[S]"
	default:
		return "[C]"
	}
}

// FormatEntry returns a display string for a marketplace entry.
func FormatEntry(e SkillEntry) string {
	stars := fmt.Sprintf("%.1f", e.Rating)
	return fmt.Sprintf("%s %s v%s  %s  %s  (%d downloads)\n    %s",
		BadgeIcon(e.Badge), e.Name, e.Version, stars, strings.Join(e.Tags, ", "),
		e.Downloads, e.Description)
}

func matchTags(tags []string, query string) bool {
	for _, t := range tags {
		if strings.Contains(strings.ToLower(t), query) {
			return true
		}
	}
	return false
}
