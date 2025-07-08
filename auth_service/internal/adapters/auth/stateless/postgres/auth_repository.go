package postgres

import (
	"context"
	"database/sql"
	"medods_test/internal/core/auth/stateless"

	_ "github.com/lib/pq"
	"fmt"
)

type PostgresAuthRepository struct {
	db                 *sql.DB
	conf               *Config
	refreshHashChecker RefreshHashChecker
}

type Config struct {
	Prefix string
}

type RefreshHashChecker interface {
	CompareHash(refreshHash, token string) bool
}

func NewPostgresAuthRepository(db *sql.DB, refreshHashChecker RefreshHashChecker, conf *Config) *PostgresAuthRepository {
	return &PostgresAuthRepository{db: db, conf: conf, refreshHashChecker: refreshHashChecker}
}

func (r *PostgresAuthRepository) SaveSession(ctx context.Context, session stateless.SessionData) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO `+r.conf.Prefix+`sls_auth_sessions (user_id, token_pair_id, refresh_hash, user_agent, ip) VALUES ($1, $2, $3, $4, $5)`,
		session.UserID, session.TokenPairID, session.RefreshHash, session.UserAgent, session.IP)
	return err
}

func (r *PostgresAuthRepository) DeleteSession(ctx context.Context, userID stateless.UserID, refreshHash string) error {
	_, err := r.db.ExecContext(ctx,
		`DELETE FROM `+r.conf.Prefix+`sls_auth_sessions WHERE user_id = $1 AND refresh_hash = $2`, userID, refreshHash)
	return err
}

func (r *PostgresAuthRepository) GetSession(ctx context.Context, userID stateless.UserID, refreshToken string) (stateless.SessionData, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT user_id, token_pair_id, refresh_hash, user_agent, ip FROM `+r.conf.Prefix+`sls_auth_sessions WHERE user_id = $1`, userID)
	if err != nil {
		return stateless.SessionData{}, err
	}
	defer rows.Close()

	for rows.Next() {
		var s stateless.SessionData
		if err := rows.Scan(&s.UserID, &s.TokenPairID, &s.RefreshHash, &s.UserAgent, &s.IP); err != nil {
			continue
		}
		if r.refreshHashChecker.CompareHash(s.RefreshHash, string(refreshToken)) {
			return s, nil
		}
	}
	return stateless.SessionData{}, sql.ErrNoRows
}
