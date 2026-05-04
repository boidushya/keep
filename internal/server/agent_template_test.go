package server

import (
	"os/exec"
	"strings"
	"testing"
)

func TestAgentScriptIsValidBash(t *testing.T) {
	t.Parallel()

	body, err := RenderAgentScript(AgentScriptParams{
		Project:      "lyrics-api",
		Env:          "prod",
		GeneratedAt:  "2026-05-04T00:00:00Z",
		Token:        "the-token",
		Endpoint:     "https://keep.example.com/render",
		Output:       "/etc/lyrics-api.env",
		ReloadCmd:    "systemctl restart lyrics-api",
		RequiredKeys: "DATABASE_URL JWT_SECRET",
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := exec.LookPath("bash"); err != nil {
		t.Skipf("bash not available: %v", err)
	}

	cmd := exec.Command("bash", "-n")
	cmd.Stdin = strings.NewReader(string(body))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bash -n rejected script: %v\noutput: %s\nscript:\n%s", err, out, body)
	}
}

func TestBootstrapInstallCommandIsValidBash(t *testing.T) {
	t.Parallel()

	script, err := RenderAgentScript(AgentScriptParams{
		Project:      "app",
		Env:          "prod",
		GeneratedAt:  "2026-05-04T00:00:00Z",
		Token:        "tok",
		Endpoint:     "https://k/render",
		Output:       "/etc/app.env",
		ReloadCmd:    "true",
		RequiredKeys: "K",
	})
	if err != nil {
		t.Fatal(err)
	}

	bootstrap := BootstrapInstallCommand(
		"app", "prod",
		string(script),
		SystemdUnitFor("app", "prod", "/usr/local/bin/keep-agent-app-prod.sh"),
		SystemdTimerFor("app", "prod"),
	)

	if _, err := exec.LookPath("bash"); err != nil {
		t.Skipf("bash not available: %v", err)
	}
	cmd := exec.Command("bash", "-n")
	cmd.Stdin = strings.NewReader(bootstrap)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bash -n rejected bootstrap: %v\noutput: %s\nbootstrap:\n%s", err, out, bootstrap)
	}

	for _, want := range []string{
		"systemctl daemon-reload",
		"systemctl enable --now keep-agent-app-prod.timer",
		"KEEP_AGENT_SCRIPT_EOF",
		"KEEP_AGENT_UNIT_EOF",
		"KEEP_AGENT_TIMER_EOF",
	} {
		if !strings.Contains(bootstrap, want) {
			t.Errorf("bootstrap missing %q", want)
		}
	}
}

func TestAgentScriptContainsKeyFields(t *testing.T) {
	t.Parallel()

	body, err := RenderAgentScript(AgentScriptParams{
		Project:      "p",
		Env:          "e",
		GeneratedAt:  "now",
		Token:        "TOK",
		Endpoint:     "ENDP",
		Output:       "/o",
		ReloadCmd:    "true",
		RequiredKeys: "K",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`TOKEN="TOK"`, `ENDPOINT="ENDP"`, `OUTPUT="/o"`, `RELOAD_CMD="true"`, `REQUIRED_KEYS="K"`} {
		if !strings.Contains(string(body), want) {
			t.Errorf("missing %q in script", want)
		}
	}
}
