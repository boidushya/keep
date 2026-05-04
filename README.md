# keep

Tiny self-hosted "secure enough" secrets manager. One Go binary and an SQLite file. Built for a single developer (me) with a single box and a handful of projects (also me).

## What it is

A no bullshit, secure web UI for projects, environments, secrets, and tokens. Agents on remote boxes pull a rendered env file from `/render` and atomically swap it in.

Built this because all other self-hosted alternatives were doing too much. I just wanna store secrets, have a web UI to manage them and a secure way to sync them to my servers without leaking everything in the process and not have it take up some insane amount of resources.
If you need exactly that, this is for you. If you need more, apologies.

## What it is not

Not for teams, orgs and definitely not a vault replacement. If you need RBAC, multi-user audit, formal compliance, or more, look elsewhere please.

## Build

```sh
make build
./keep
```

First run walks you through setup at `http://localhost:4339`.

### Config

| env var | default | meaning |
| --- | --- | --- |
| `KEEP_DB_PATH` | `./keep.db` | path to the SQLite database |
| `KEEP_LISTEN` | `:4339` | listen address |
| `KEEP_PUBLIC_URL` | `http://localhost:4339` | externally-visible URL embedded in generated agent scripts |
| `KEEP_SESSION_DURATION` | `720h` | how long signed-cookie sessions remain valid |
| `KEEP_SECURE_COOKIES` | auto | set the `Secure` flag on cookies. Defaults to true iff `KEEP_PUBLIC_URL` starts with `https://`. Override with `true`/`false`. |

LICENSE: [MIT](LICENSE)
