CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    password_hash TEXT NOT NULL,
    totp_secret_encrypted BLOB NOT NULL,
    recovery_codes_encrypted BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    last_login_at INTEGER
);

CREATE TABLE master_key_envelope (
    id INTEGER PRIMARY KEY,
    salt BLOB NOT NULL,
    wrapped_key BLOB NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE envs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    slug TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (project_id, slug)
);

CREATE TABLE secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    env_id INTEGER NOT NULL REFERENCES envs(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    value_encrypted BLOB NOT NULL,
    current_version INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (env_id, key)
);

CREATE TABLE secret_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    secret_id INTEGER NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    value_encrypted BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    created_by_user_id INTEGER REFERENCES users(id),
    UNIQUE (secret_id, version)
);

CREATE TABLE tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    env_id INTEGER NOT NULL REFERENCES envs(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    hashed_token TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER,
    expires_at INTEGER,
    revoked_at INTEGER
);

CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at INTEGER NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    metadata TEXT NOT NULL
);

CREATE INDEX idx_audit_at ON audit_log(at DESC);
CREATE INDEX idx_secret_versions_secret ON secret_versions(secret_id, version DESC);
