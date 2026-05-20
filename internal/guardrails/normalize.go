package guardrails

import (
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strings"
)

// zeroWidthRunes are invisible characters attackers splice between letters to
// break up keywords and slip past ASCII pattern matching.
var zeroWidthRunes = map[rune]bool{
	'​':      true, // zero-width space
	'‌':      true, // zero-width non-joiner
	'‍':      true, // zero-width joiner
	'⁠':      true, // word joiner
	'\uFEFF': true, // zero-width no-break space / BOM
	'­':      true, // soft hyphen
	'᠎':      true, // mongolian vowel separator
	'͏':      true, // combining grapheme joiner
}

// homoglyphs maps confusable Unicode letters to their ASCII equivalents.
// Swapping a Latin "o" for a Cyrillic "о" renders identically but evades an
// ASCII regex, so detection folds them back before matching.
var homoglyphs = map[rune]rune{
	// Cyrillic lowercase
	'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p',
	'х': 'x', 'у': 'y', 'і': 'i', 'ѕ': 's', 'ј': 'j',
	'һ': 'h', 'ԁ': 'd', 'ո': 'n',
	// Cyrillic uppercase
	'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M',
	'Н': 'H', 'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T',
	'Х': 'X', 'У': 'Y', 'І': 'I', 'Ј': 'J',
	// Greek
	'ο': 'o', 'ρ': 'p', 'α': 'a', 'ε': 'e', 'ν': 'v',
	'ι': 'i', 'Ι': 'I', 'Ο': 'O', 'Α': 'A', 'Β': 'B',
	'Ε': 'E', 'Η': 'H', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N',
	'Ρ': 'P', 'Τ': 'T', 'Χ': 'X', 'Ζ': 'Z',
	// Latin script confusables
	'ɡ': 'g', 'ⅼ': 'l', 'ⅰ': 'i',
}

// stripInvisible removes zero-width and other invisible characters.
func stripInvisible(s string) string {
	return strings.Map(func(r rune) rune {
		if zeroWidthRunes[r] {
			return -1
		}
		return r
	}, s)
}

// foldConfusables rewrites homoglyphs and fullwidth characters to plain ASCII.
func foldConfusables(s string) string {
	return strings.Map(func(r rune) rune {
		if ascii, ok := homoglyphs[r]; ok {
			return ascii
		}
		switch {
		case r >= 'Ａ' && r <= 'Ｚ': // fullwidth A-Z
			return r - 0xFF21 + 'A'
		case r >= 'ａ' && r <= 'ｚ': // fullwidth a-z
			return r - 0xFF41 + 'a'
		case r >= '０' && r <= '９': // fullwidth 0-9
			return r - 0xFF10 + '0'
		}
		return r
	}, s)
}

var whitespaceRun = regexp.MustCompile(`\s+`)

// collapseSpace flattens runs of whitespace to a single space.
func collapseSpace(s string) string {
	return strings.TrimSpace(whitespaceRun.ReplaceAllString(s, " "))
}

// normalize returns text with evasion tricks neutralised: invisible characters
// stripped, confusable glyphs folded to ASCII, and whitespace collapsed.
func normalize(s string) string {
	return collapseSpace(foldConfusables(stripInvisible(s)))
}

var allSeparators = regexp.MustCompile(`[\s.,_*|~/\\()\[\]{}<>:;!?'"+=-]+`)

// compact strips all whitespace and separator punctuation, folding a fully
// spaced-out phrase ("i g n o r e   a l l") back into one solid lowercase
// string for signature matching.
func compact(s string) string {
	folded := foldConfusables(stripInvisible(s))
	return strings.ToLower(allSeparators.ReplaceAllString(folded, ""))
}

var (
	base64Blob = regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)
	hexBlob    = regexp.MustCompile(`(?:[0-9A-Fa-f]{2}){16,}`)
)

// isMostlyPrintable reports whether a decoded byte slice is plausible text
// rather than binary noise, so random base64-looking tokens are ignored.
func isMostlyPrintable(b []byte) bool {
	if len(b) < 8 {
		return false
	}
	printable := 0
	for _, c := range b {
		if c == '\t' || c == '\n' || c == '\r' || (c >= 0x20 && c < 0x7f) {
			printable++
		}
	}
	return printable*100/len(b) >= 85
}

// decodeEmbedded extracts and decodes base64 and hex blobs so that injection
// payloads smuggled in an encoded form can still be inspected.
func decodeEmbedded(s string) []string {
	var out []string
	for _, m := range base64Blob.FindAllString(s, -1) {
		trimmed := strings.TrimRight(m, "=")
		for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
			if dec, err := enc.DecodeString(trimmed); err == nil && isMostlyPrintable(dec) {
				out = append(out, string(dec))
				break
			}
		}
	}
	for _, m := range hexBlob.FindAllString(s, -1) {
		if dec, err := hex.DecodeString(m); err == nil && isMostlyPrintable(dec) {
			out = append(out, string(dec))
		}
	}
	return out
}

// scanText holds the variants of a piece of text used for evasion-resistant
// matching: the original, a normalised form, and any decoded base64/hex
// payloads.
type scanText struct {
	variants []string
}

func newScanText(s string) scanText {
	variants := []string{s}
	seen := map[string]bool{s: true}
	add := func(v string) {
		if v != "" && !seen[v] {
			seen[v] = true
			variants = append(variants, v)
		}
	}
	add(normalize(s))
	for _, dec := range decodeEmbedded(s) {
		add(dec)
		add(normalize(dec))
	}
	return scanText{variants: variants}
}

// find reports whether pat matches any variant. When the match is in the
// original text the real character span is returned; a match found only after
// de-obfuscation reports evaded=true with a zero span.
func (st scanText) find(pat *regexp.Regexp) (span [2]int, matched, evaded bool) {
	for i, v := range st.variants {
		loc := pat.FindStringIndex(v)
		if loc == nil {
			continue
		}
		if i == 0 {
			return [2]int{loc[0], loc[1]}, true, false
		}
		return [2]int{0, 0}, true, true
	}
	return [2]int{0, 0}, false, false
}
