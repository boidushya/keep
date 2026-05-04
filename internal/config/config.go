// Package config loads keep's runtime config from environment variables.
// Defaults are tuned for "single dev, single box".
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds the values keep reads at boot.
type Config struct {
	DBPath          string        // KEEP_DB_PATH, default "./keep.db"
	Listen          string        // KEEP_LISTEN, default ":4339"
	PublicURL       string        // KEEP_PUBLIC_URL, default "http://localhost:4339"
	SessionDuration time.Duration // KEEP_SESSION_DURATION, default 720h (30d)
	SecureCookies   bool          // KEEP_SECURE_COOKIES, default true iff PublicURL is https://
}

// Load reads env vars and returns a Config with defaults filled in.
func Load() (Config, error) {
	c := Config{
		DBPath:          getenv("KEEP_DB_PATH", "./keep.db"),
		Listen:          getenv("KEEP_LISTEN", ":4339"),
		PublicURL:       strings.TrimRight(getenv("KEEP_PUBLIC_URL", "http://localhost:4339"), "/"),
		SessionDuration: 720 * time.Hour,
	}
	if d := os.Getenv("KEEP_SESSION_DURATION"); d != "" {
		parsed, err := time.ParseDuration(d)
		if err != nil {
			return Config{}, fmt.Errorf("KEEP_SESSION_DURATION: %w", err)
		}
		c.SessionDuration = parsed
	}

	// Default cookie security to "match the URL scheme": HTTPS public URL
	// implies Secure cookies. Explicit env wins.
	c.SecureCookies = strings.HasPrefix(c.PublicURL, "https://")
	if v := os.Getenv("KEEP_SECURE_COOKIES"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, fmt.Errorf("KEEP_SECURE_COOKIES: %w", err)
		}
		c.SecureCookies = b
	}

	return c, nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
