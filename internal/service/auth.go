package service

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/allnqq/pcclub-auth/internal/domain"
	"github.com/allnqq/pcclub-shared/pkg/errors"
)

type UserRepo interface {
	Create(ctx context.Context, user *domain.User) error
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
	GetByID(ctx context.Context, id string) (*domain.User, error)
	GetByPhone(ctx context.Context, phone string) (*domain.User, error)
	UpdatePassword(ctx context.Context, id, passwordHash string) error
}

type TokenRepo interface {
	Create(ctx context.Context, token *domain.RefreshToken) error
	GetByToken(ctx context.Context, token string) (*domain.RefreshToken, error)
	Delete(ctx context.Context, token string) error
}

type AuthService struct {
	userRepo  UserRepo
	tokenRepo TokenRepo
	jwtSecret string
}

func NewAuthService(userRepo UserRepo, tokenRepo TokenRepo, jwtSecret string) *AuthService {
	return &AuthService{userRepo: userRepo, tokenRepo: tokenRepo, jwtSecret: jwtSecret}
}

func (s *AuthService) Register(ctx context.Context, name, email, phone, password string) error {
	_, err := s.userRepo.GetByEmail(ctx, email)
	if err == nil {
		return errors.ErrAlreadyExists
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return errors.ErrInternal
	}

	user := &domain.User{
		Name:         name,
		Email:        email,
		Phone:        phone,
		PasswordHash: string(hash),
		Role:         domain.RoleUser,
	}
	return s.userRepo.Create(ctx, user)
}

func (s *AuthService) Login(ctx context.Context, email, password string) (string, string, error) {
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		return "", "", errors.ErrUnauthorized
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return "", "", errors.ErrUnauthorized
	}

	accessToken, err := s.generateAccessToken(user)
	if err != nil {
		return "", "", errors.ErrInternal
	}

	refreshToken := uuid.New().String()
	err = s.tokenRepo.Create(ctx, &domain.RefreshToken{
		UserID:    user.ID,
		Token:     refreshToken,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	})
	if err != nil {
		return "", "", errors.ErrInternal
	}

	return accessToken, refreshToken, nil
}

func (s *AuthService) Refresh(ctx context.Context, refreshToken string) (string, error) {
	t, err := s.tokenRepo.GetByToken(ctx, refreshToken)
	if err != nil {
		return "", errors.ErrUnauthorized
	}

	if time.Now().After(t.ExpiresAt) {
		return "", errors.ErrUnauthorized
	}

	user, err := s.userRepo.GetByID(ctx, t.UserID)
	if err != nil {
		return "", errors.ErrUnauthorized
	}

	return s.generateAccessToken(user)
}

func (s *AuthService) ResetPassword(ctx context.Context, email, newPassword string) error {
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		return errors.ErrNotFound
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return errors.ErrInternal
	}

	return s.userRepo.UpdatePassword(ctx, user.ID, string(hash))
}

func (s *AuthService) generateAccessToken(user *domain.User) (string, error) {
	claims := jwt.MapClaims{
		"user_id": user.ID,
		"role":    user.Role,
		"exp":     time.Now().Add(15 * time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.jwtSecret))
}