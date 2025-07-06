package postgres

import (
	"database/sql"
	"medods_test/internal/core/auth/stateless"

	_ "github.com/lib/pq"
)

type PostgresAuthRepository struct {
	db   *sql.DB
	conf *Config
}

type Config struct {
	Prefix string
}

func NewPostgresAuthRepository(db *sql.DB, conf *Config) *PostgresAuthRepository {
	return &PostgresAuthRepository{db: db, conf: conf}
}

func (r *PostgresAuthRepository) SaveSession(session stateless.SessionData) error {
	_, err := r.db.Exec(`INSERT INTO `+r.conf.Prefix+`sls_auth_sessions (user_id, token_pair_id, refresh_hash, user_agent, ip) VALUES ($1, $2, $3, $4, $5)`,
		session.UserID, session.TokenPairID, session.RefreshHash, session.UserAgent, session.IP)
	return err
}

func (r *PostgresAuthRepository) DeleteSession(userID stateless.UserID, refreshHash string) error {
	_, err := r.db.Exec(`DELETE FROM `+r.conf.Prefix+`sls_auth_sessions WHERE user_id = $1 AND refresh_hash = $2`, userID, refreshHash)
	return err
}

func (r *PostgresAuthRepository) GetSession(userID stateless.UserID, refreshHash string) (stateless.SessionData, error) {
	row := r.db.QueryRow(`SELECT user_id, token_pair_id, refresh_hash, user_agent, ip FROM `+r.conf.Prefix+`sls_auth_sessions WHERE user_id = $1 AND refresh_hash = $2`, userID, refreshHash)
	var s stateless.SessionData
	if err := row.Scan(&s.UserID, &s.TokenPairID, &s.RefreshHash, &s.UserAgent, &s.IP); err != nil {
		return stateless.SessionData{}, err
	}
	return s, nil
}
