package repository

import (
	"context"

	"github.com/jmoiron/sqlx"
	"github.com/allnqq/pcclub-auth/internal/domain"
)

type TokenRepository struct {
	db *sqlx.DB
}

func NewTokenRepository(db *sqlx.DB) *TokenRepository {
	return &TokenRepository{db: db}
}

func (r *TokenRepository) Create(ctx context.Context, token *domain.RefreshToken) error {
	query := `INSERT INTO refresh_tokens (user_id, token, expires_at)
		VALUES (:user_id, :token, :expires_at)`
	_, err := r.db.NamedExecContext(ctx, query, token)
	return err
}

func (r *TokenRepository) GetByToken(ctx context.Context, token string) (*domain.RefreshToken, error) {
	var t domain.RefreshToken
	err := r.db.GetContext(ctx, &t, "SELECT * FROM refresh_tokens WHERE token=$1", token)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (r *TokenRepository) Delete(ctx context.Context, token string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM refresh_tokens WHERE token=$1", token)
	return err
}