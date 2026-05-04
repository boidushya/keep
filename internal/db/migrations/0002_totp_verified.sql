-- Track whether the user has confirmed their TOTP setup by entering a code
-- from their authenticator app. Setup is incomplete until totp_verified = 1;
-- recovery codes do NOT count as confirmation.
ALTER TABLE users ADD COLUMN totp_verified INTEGER NOT NULL DEFAULT 0;
