package repository

import (
	"context"

	"github.com/jmoiron/sqlx"
	"github.com/allnqq/pcclub-auth/internal/domain"
)

type UserRepository struct {
	db *sqlx.DB
}

func NewUserRepository(db *sqlx.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, user *domain.User) error {
	query := `INSERT INTO users (name, email, phone, password_hash, role)
		VALUES (:name, :email, :phone, :password_hash, :role)`
	_, err := r.db.NamedExecContext(ctx, query, user)
	return err
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	var user domain.User
	err := r.db.GetContext(ctx, &user, "SELECT * FROM users WHERE email=$1", email)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) GetByID(ctx context.Context, id string) (*domain.User, error) {
	var user domain.User
	err := r.db.GetContext(ctx, &user, "SELECT * FROM users WHERE id=$1", id)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) GetByPhone(ctx context.Context, phone string) (*domain.User, error) {
	var user domain.User
	err := r.db.GetContext(ctx, &user, "SELECT * FROM users WHERE phone=$1", phone)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) UpdatePassword(ctx context.Context, id, passwordHash string) error {
	_, err := r.db.ExecContext(ctx, "UPDATE users SET password_hash=$1, updated_at=now() WHERE id=$2", passwordHash, id)
	return err
}