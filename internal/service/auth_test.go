package service

import (
	"context"
	"testing"
	"time"

	"github.com/allnqq/pcclub-auth/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

// Моки — имитируют репозитории без реальной БД
type MockUserRepo struct {
	mock.Mock
}

func (m *MockUserRepo) Create(ctx context.Context, user *domain.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepo) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepo) GetByID(ctx context.Context, id string) (*domain.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepo) GetByPhone(ctx context.Context, phone string) (*domain.User, error) {
	args := m.Called(ctx, phone)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepo) UpdatePassword(ctx context.Context, id, passwordHash string) error {
	args := m.Called(ctx, id, passwordHash)
	return args.Error(0)
}

type MockTokenRepo struct {
	mock.Mock
}

func (m *MockTokenRepo) Create(ctx context.Context, token *domain.RefreshToken) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func (m *MockTokenRepo) GetByToken(ctx context.Context, token string) (*domain.RefreshToken, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.RefreshToken), args.Error(1)
}

func (m *MockTokenRepo) Delete(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

// Тесты
func TestRegister_Success(t *testing.T) {
	userRepo := new(MockUserRepo)
	tokenRepo := new(MockTokenRepo)
	svc := NewAuthService(userRepo, tokenRepo, "secret")

	userRepo.On("GetByEmail", mock.Anything, "test@test.com").Return(nil, assert.AnError)
	userRepo.On("Create", mock.Anything, mock.AnythingOfType("*domain.User")).Return(nil)

	err := svc.Register(context.Background(), "Test", "test@test.com", "79991234567", "password")
	assert.NoError(t, err)
	userRepo.AssertExpectations(t)
}

func TestRegister_AlreadyExists(t *testing.T) {
	userRepo := new(MockUserRepo)
	tokenRepo := new(MockTokenRepo)
	svc := NewAuthService(userRepo, tokenRepo, "secret")

	userRepo.On("GetByEmail", mock.Anything, "test@test.com").Return(&domain.User{}, nil)

	err := svc.Register(context.Background(), "Test", "test@test.com", "79991234567", "password")
	assert.Error(t, err)
}

func TestLogin_Success(t *testing.T) {
	userRepo := new(MockUserRepo)
	tokenRepo := new(MockTokenRepo)
	svc := NewAuthService(userRepo, tokenRepo, "secret")

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	user := &domain.User{
		ID:           "123",
		Email:        "test@test.com",
		PasswordHash: string(hashedPassword),
		Role:         domain.RoleUser,
	}

	userRepo.On("GetByEmail", mock.Anything, "test@test.com").Return(user, nil)
	tokenRepo.On("Create", mock.Anything, mock.AnythingOfType("*domain.RefreshToken")).Return(nil)

	access, refresh, err := svc.Login(context.Background(), "test@test.com", "password")
	assert.NoError(t, err)
	assert.NotEmpty(t, access)
	assert.NotEmpty(t, refresh)
}

func TestLogin_WrongPassword(t *testing.T) {
	userRepo := new(MockUserRepo)
	tokenRepo := new(MockTokenRepo)
	svc := NewAuthService(userRepo, tokenRepo, "secret")

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	user := &domain.User{
		ID:           "123",
		Email:        "test@test.com",
		PasswordHash: string(hashedPassword),
	}

	userRepo.On("GetByEmail", mock.Anything, "test@test.com").Return(user, nil)

	_, _, err := svc.Login(context.Background(), "test@test.com", "wrongpassword")
	assert.Error(t, err)
}

func TestRefresh_Expired(t *testing.T) {
	userRepo := new(MockUserRepo)
	tokenRepo := new(MockTokenRepo)
	svc := NewAuthService(userRepo, tokenRepo, "secret")

	expiredToken := &domain.RefreshToken{
		UserID:    "123",
		Token:     "expiredtoken",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}

	tokenRepo.On("GetByToken", mock.Anything, "expiredtoken").Return(expiredToken, nil)

	_, err := svc.Refresh(context.Background(), "expiredtoken")
	assert.Error(t, err)
}

func TestResetPassword_UserNotFound(t *testing.T) {
	userRepo := new(MockUserRepo)
	tokenRepo := new(MockTokenRepo)
	svc := NewAuthService(userRepo, tokenRepo, "secret")

	userRepo.On("GetByEmail", mock.Anything, "notexist@test.com").Return(nil, assert.AnError)

	err := svc.ResetPassword(context.Background(), "notexist@test.com", "newpassword")
	assert.Error(t, err)
}