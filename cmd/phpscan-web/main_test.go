package main

import "testing"

func TestParseTarget(t *testing.T) {
	for raw, want := range map[string]string{
		"example.com":                "https://example.com",
		" http://example.com/a.php ": "http://example.com/a.php",
		"https://example.com:443/":   "https://example.com:443/",
		"example.com:22":             "",
		"ftp://example.com":          "",
		"file:///etc/passwd":         "",
		"":                           "",
	} {
		got, err := parseTarget(raw)
		if got != want || (err != nil) != (want == "") {
			t.Errorf("parseTarget(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
}
