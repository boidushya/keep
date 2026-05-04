# Self-hosting keep

I built this for one box and one person (me). These notes assume the same shape. If your setup is different, the broad strokes still apply but the specifics will drift.

## What you'll need

- A box with a public IP and a domain pointing at it
- TLS in front of keep (Caddy is easiest; nginx works fine)
- Go 1.22+ to build, or a prebuilt binary
- A TOTP app on your phone (2FAS, 1Password, Authy, whatever you trust)
- A password manager to hold the master password and recovery codes

Don't run keep on plain HTTP outside of local testing. Sessions and TOTP only make sense behind TLS.

## First run

```sh
make build
./keep
```

You'll see something like `keep listening on :4339, public URL http://localhost:4339`. Open that URL. You'll land on `/setup`. Three things happen:

1. **Pick a master password.** This is the key to everything. There is no reset flow. Lose it and the database is just encrypted bytes.
2. **Scan the TOTP QR code.** Save the 8 recovery codes shown underneath. They bypass TOTP if you lose your phone, but they don't bypass the master password.
3. **Confirm the TOTP code.** keep makes you type a current 6-digit code from the authenticator before it accepts setup. Recovery codes are explicitly rejected on this step. The point is to make sure your authenticator actually has the secret saved before keep moves on.

After that, login is master password then TOTP, every time.

## Putting it behind TLS

Caddy:

```Caddyfile
keep.example.com {
    reverse_proxy localhost:4339
}
```

Then run keep with the public URL set:

```sh
KEEP_PUBLIC_URL=https://keep.example.com ./keep
```

`KEEP_PUBLIC_URL` matters in two places:

1. It flips the `Secure` cookie flag on by default (you can override with `KEEP_SECURE_COOKIES=true|false`).
2. It's baked into agent install scripts, so the agents on remote boxes know where to call `/render`.

## systemd

`/etc/systemd/system/keep.service`:

```ini
[Unit]
Description=keep
After=network.target

[Service]
ExecStart=/usr/local/bin/keep
Environment=KEEP_DB_PATH=/var/lib/keep/keep.db
Environment=KEEP_PUBLIC_URL=https://keep.example.com
Environment=KEEP_LISTEN=:4339
WorkingDirectory=/var/lib/keep
User=keep
Group=keep
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/keep

[Install]
WantedBy=multi-user.target
```

```sh
sudo useradd -r -s /usr/sbin/nologin -d /var/lib/keep keep
sudo install -d -o keep -g keep /var/lib/keep
sudo install -o root -g root -m 0755 keep /usr/local/bin/keep
sudo systemctl daemon-reload
sudo systemctl enable --now keep
```

Read the next section before you go further. There's a thing about restarts.

## Sealed-state caveat

When the keep process starts, it has no master key in memory. The age identity that decrypts secret values is wrapped on disk by a key derived from your master password. Until you log in via the UI, the vault stays sealed and `/render` returns:

```
HTTP/1.1 503 Service Unavailable

keep is sealed: operator must log in to unlock
```

Practically: after a reboot or `systemctl restart keep`, your agents will fail to pull until you log in via the browser once. The apps consuming those env files keep running with whatever was last written to disk, so this is a "secrets stop rolling" problem, not an "everything goes down" problem. Still, add an "open keep, log in, unseal" step to whatever post-reboot checklist you have.

I'd rather have this than stash the unwrap key on disk. If you reboot the box, you re-enter the password once. If reboots are frequent enough that this is annoying, the right answer is `systemd-creds` with TPM2 sealing (not implemented yet, feel free to contribute!).

## Adding agents

An agent pulls one project/env onto one target box. The keep UI generates everything you need.

1. Open the project, pick the env, click **Tokens**.
2. Mint a token: name, expiry, target file path (commonly `/etc/<project>.env`), reload command (`systemctl restart myapp`), and the keys the env file must contain.
3. Copy the install command and paste it into a root shell on the target box.

That command writes three files:

- `/usr/local/bin/keep-agent-<project>-<env>.sh`
- `/etc/systemd/system/keep-agent-<project>-<env>.service`
- `/etc/systemd/system/keep-agent-<project>-<env>.timer`

The timer fires 30 seconds after boot and every 60 seconds after that. The agent fetches `/render`, validates that all required keys are present, and only triggers your reload command if the rendered file actually changed. So most of the runs are no-ops.

To check it:

```sh
systemctl status keep-agent-<project>-<env>.timer
journalctl -u keep-agent-<project>-<env>.service -n 50
```

If the env never lands, look for the obvious things first: token revoked, env or project deleted, keep process sealed, required keys missing.

## Backups

Back up the database file (`KEEP_DB_PATH`). That's it.

- Secret values are encrypted at rest. A leaked backup is useless without the master password.
- Tokens are stored as sha-256 hashes of 32-byte random values, so a leaked backup doesn't grant API access either.
- Audit log entries hold metadata only (who touched what when), no values.

Use SQLite's `.backup` (online), or stop the process, copy the file, restart. For one box I just rclone the file to B2 once an hour from a cron. SQLite is small. Don't overthink this.

Important: store the master password and the database backup in different places. If both end up in the same compromised vault, you've handed someone the keys and the lock.

## Updating

```sh
sudo systemctl stop keep
sudo install -m 0755 keep /usr/local/bin/keep
sudo systemctl start keep
```

Migrations run automatically on startup. They're embedded in the binary, so a new version brings its own. After the restart, log in once to unseal.

## Recovery scenarios

**Lost TOTP device, still have master password.** Go to `/login/recovery`. Type the master password and one recovery code. You're back in. That code is now consumed. You started with 8.

**Lost master password.** The vault is sealed forever. There is no reset. If you have a `.db` backup whose master password you remember, restore it. Otherwise wipe the file and start over.

**Lost both.** Wipe the file and start over.

**Used most of your recovery codes.** There's no UI to regenerate them yet. Treat the initial 8 as a budget. If you've burned through several and want a fresh batch, the workaround today is to wipe the user row and re-run setup. (Yes, this is a TODO, kinda)

## Audit log

Every secret read, write, version restore, and token mint goes into a local audit log with timestamp, actor, and action. It's in the same SQLite database, so backups cover it. View it from the UI header.

There's no log shipping. If you want it in Loki or wherever, tail the SQLite table or the systemd journal.

## Things keep doesn't do

- Multiple users
- Roles or per-secret ACLs
- High availability or clustering
- KMS-backed unwrapping
- Auto-rotation
- Webhooks or notifications
- A CLI for the server side (only the agent is shell)

If any of those are dealbreakers, run something else. keep replaced a pile of `.env` files and an ssh-and-vim workflow. It's intentionally small.
