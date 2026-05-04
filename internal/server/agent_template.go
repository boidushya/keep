package server

import (
	"bytes"
	"fmt"
	"text/template"
	"time"
)

// AgentScriptParams is the input to the bash agent template. The values are
// substituted verbatim, so callers must not include shell-significant
// characters they did not vet.
type AgentScriptParams struct {
	Project      string
	Env          string
	GeneratedAt  string
	Token        string
	Endpoint     string
	Output       string
	ReloadCmd    string
	RequiredKeys string
}

// agentScriptTmpl matches the deployment shape used by better-lyrics-api: stage
// to a temp file, validate, atomic move, chmod 600, run reload.
var agentScriptTmpl = template.Must(template.New("agent").Parse(`#!/usr/bin/env bash
# keep agent for {{.Project}}/{{.Env}}
# generated {{.GeneratedAt}}
set -euo pipefail

TOKEN={{printf "%q" .Token}}
ENDPOINT={{printf "%q" .Endpoint}}
OUTPUT={{printf "%q" .Output}}
RELOAD_CMD={{printf "%q" .ReloadCmd}}
REQUIRED_KEYS={{printf "%q" .RequiredKeys}}

STAGED="${OUTPUT}.staging"
BAK="${OUTPUT}.bak"

curl -fsSL --max-time 15 -H "Authorization: Bearer $TOKEN" "$ENDPOINT" -o "$STAGED"

if [[ ! -s "$STAGED" ]]; then
    echo "[keep-agent] ERROR: empty response" >&2
    rm -f "$STAGED"; exit 1
fi

for k in $REQUIRED_KEYS; do
    if ! grep -q "^${k}=" "$STAGED"; then
        echo "[keep-agent] ERROR: missing required key $k" >&2
        rm -f "$STAGED"; exit 1
    fi
done

if [[ -f "$OUTPUT" ]] && diff -q "$OUTPUT" "$STAGED" >/dev/null 2>&1; then
    rm -f "$STAGED"
    exit 0
fi

[[ -f "$OUTPUT" ]] && cp "$OUTPUT" "$BAK"
mv "$STAGED" "$OUTPUT"
chmod 600 "$OUTPUT"

eval "$RELOAD_CMD"
echo "[keep-agent] reloaded $(date -u +%FT%TZ)"
`))

// RenderAgentScript expands agentScriptTmpl with p and returns the resulting
// shell script.
func RenderAgentScript(p AgentScriptParams) ([]byte, error) {
	if p.GeneratedAt == "" {
		p.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	}
	var buf bytes.Buffer
	if err := agentScriptTmpl.Execute(&buf, p); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// SystemdUnitFor returns the systemd .service body for an agent.
func SystemdUnitFor(project, env, scriptPath string) string {
	return fmt.Sprintf(`# /etc/systemd/system/keep-agent-%s-%s.service
[Unit]
Description=keep agent for %s/%s
After=network.target

[Service]
Type=oneshot
ExecStart=%s
`, project, env, project, env, scriptPath)
}

// SystemdTimerFor returns the systemd .timer body for an agent.
func SystemdTimerFor(project, env string) string {
	return fmt.Sprintf(`# /etc/systemd/system/keep-agent-%s-%s.timer
[Unit]
Description=keep agent timer for %s/%s

[Timer]
OnBootSec=30s
OnUnitActiveSec=60s

[Install]
WantedBy=timers.target
`, project, env, project, env)
}

// BootstrapInstallCommand returns a single bash command (paste-and-run) that
// writes the agent script, the systemd unit, and the systemd timer, then
// reloads and starts the timer.
func BootstrapInstallCommand(project, env, agentScript, unit, timer string) string {
	scriptPath := "/usr/local/bin/keep-agent-" + project + "-" + env + ".sh"
	unitPath := "/etc/systemd/system/keep-agent-" + project + "-" + env + ".service"
	timerPath := "/etc/systemd/system/keep-agent-" + project + "-" + env + ".timer"
	timerName := "keep-agent-" + project + "-" + env + ".timer"

	return fmt.Sprintf(`set -euo pipefail

sudo install -d /usr/local/bin /etc/systemd/system

sudo tee %s >/dev/null <<'KEEP_AGENT_SCRIPT_EOF'
%sKEEP_AGENT_SCRIPT_EOF
sudo chmod 0755 %s

sudo tee %s >/dev/null <<'KEEP_AGENT_UNIT_EOF'
%sKEEP_AGENT_UNIT_EOF

sudo tee %s >/dev/null <<'KEEP_AGENT_TIMER_EOF'
%sKEEP_AGENT_TIMER_EOF

sudo systemctl daemon-reload
sudo systemctl enable --now %s
sudo systemctl status %s --no-pager
`, scriptPath, agentScript, scriptPath, unitPath, unit, timerPath, timer, timerName, timerName)
}
