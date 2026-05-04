package server

import (
	"fmt"
	"strings"
)

type dotenvEntry struct {
	key   string
	value string
}

func parseDotenv(raw string) ([]dotenvEntry, error) {
	var out []dotenvEntry
	for i, line := range strings.Split(raw, "\n") {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		eq := strings.IndexByte(s, '=')
		if eq <= 0 {
			return nil, fmt.Errorf("line %d: missing =", i+1)
		}
		key := strings.TrimSpace(s[:eq])
		val := strings.TrimSpace(s[eq+1:])
		if !keyRE.MatchString(key) {
			return nil, fmt.Errorf("line %d: invalid key %q", i+1, key)
		}
		val = stripQuotes(val)
		if val == "" {
			return nil, fmt.Errorf("line %d: empty value for %s", i+1, key)
		}
		out = append(out, dotenvEntry{key: key, value: val})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no entries")
	}
	return out, nil
}

func stripQuotes(s string) string {
	if len(s) < 2 {
		return s
	}
	first, last := s[0], s[len(s)-1]
	if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}
