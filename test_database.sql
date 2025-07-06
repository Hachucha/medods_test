CREATE TABLE IF NOT EXISTS sls_auth_sessions (
    user_id       UUID      NOT NULL,
    token_pair_id UUID      NOT NULL,
    refresh_hash  TEXT      NOT NULL,
    user_agent    TEXT      NOT NULL,
    ip            inet      NOT NULL,
    PRIMARY KEY (user_id, refresh_hash)
);
