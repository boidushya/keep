package config

import (
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("KEEP_DB_PATH", "")
	t.Setenv("KEEP_LISTEN", "")
	t.Setenv("KEEP_PUBLIC_URL", "")
	t.Setenv("KEEP_SESSION_DURATION", "")
	t.Setenv("KEEP_SECURE_COOKIES", "")

	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.DBPath != "./keep.db" {
		t.Errorf("DBPath = %q", c.DBPath)
	}
	if c.Listen != ":4339" {
		t.Errorf("Listen = %q", c.Listen)
	}
	if c.PublicURL != "http://localhost:4339" {
		t.Errorf("PublicURL = %q", c.PublicURL)
	}
	if c.SessionDuration != 720*time.Hour {
		t.Errorf("SessionDuration = %s", c.SessionDuration)
	}
	if c.SecureCookies {
		t.Errorf("SecureCookies should be false on default http URL")
	}
}

func TestSecureCookiesAutoDerivedFromHTTPS(t *testing.T) {
	t.Setenv("KEEP_PUBLIC_URL", "https://keep.boidu.dev")
	t.Setenv("KEEP_SECURE_COOKIES", "")

	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !c.SecureCookies {
		t.Error("SecureCookies should auto-default to true for https URL")
	}
}

func TestSecureCookiesExplicitEnvWins(t *testing.T) {
	t.Setenv("KEEP_PUBLIC_URL", "https://keep.boidu.dev")
	t.Setenv("KEEP_SECURE_COOKIES", "false")

	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.SecureCookies {
		t.Error("explicit KEEP_SECURE_COOKIES=false should override https default")
	}
}

func TestSecureCookiesRejectsBadValue(t *testing.T) {
	t.Setenv("KEEP_SECURE_COOKIES", "perhaps")
	if _, err := Load(); err == nil {
		t.Fatal("expected error for non-boolean value")
	}
}

func TestLoadOverrides(t *testing.T) {
	t.Setenv("KEEP_DB_PATH", "/srv/keep/keep.db")
	t.Setenv("KEEP_LISTEN", ":9090")
	t.Setenv("KEEP_PUBLIC_URL", "https://keep.example.com/")
	t.Setenv("KEEP_SESSION_DURATION", "12h")

	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.DBPath != "/srv/keep/keep.db" {
		t.Errorf("DBPath = %q", c.DBPath)
	}
	if c.Listen != ":9090" {
		t.Errorf("Listen = %q", c.Listen)
	}
	if c.PublicURL != "https://keep.example.com" {
		t.Errorf("PublicURL = %q (expected trailing slash trimmed)", c.PublicURL)
	}
	if c.SessionDuration != 12*time.Hour {
		t.Errorf("SessionDuration = %s", c.SessionDuration)
	}
}

func TestLoadRejectsBadDuration(t *testing.T) {
	t.Setenv("KEEP_SESSION_DURATION", "not-a-duration")
	if _, err := Load(); err == nil {
		t.Fatal("expected error for malformed duration")
	}
}
