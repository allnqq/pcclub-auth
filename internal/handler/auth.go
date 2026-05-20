package handler

import (
	"encoding/json"
	"net/http"

	"github.com/allnqq/pcclub-auth/internal/service"
	"github.com/allnqq/pcclub-shared/pkg/errors"
	"github.com/allnqq/pcclub-shared/pkg/logger"
	"github.com/allnqq/pcclub-shared/pkg/response"
	"go.uber.org/zap"
)

type AuthHandler struct {
	service *service.AuthService
}

func NewAuthHandler(service *service.AuthService) *AuthHandler {
	return &AuthHandler{service: service}
}

type registerRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Password string `json:"password"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type resetPasswordRequest struct {
	Email       string `json:"email"`
	NewPassword string `json:"new_password"`
}

// Register godoc
// @Summary Регистрация пользователя
// @Tags auth
// @Accept json
// @Produce json
// @Param input body registerRequest true "Данные пользователя"
// @Success 200 {object} map[string]interface{}
// @Router /auth/register [post]
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "invalid request")
		return
	}

	if req.Name == "" || req.Email == "" || req.Phone == "" || req.Password == "" {
		response.Error(w, http.StatusBadRequest, "all fields are required")
		return
	}

	err := h.service.Register(r.Context(), req.Name, req.Email, req.Phone, req.Password)
	if err != nil {
		if err == errors.ErrAlreadyExists {
			response.Error(w, http.StatusConflict, "user already exists")
			return
		}
		logger.Error("register error", zap.Error(err))
		response.Error(w, http.StatusInternalServerError, "internal error")
		return
	}

	response.JSON(w, http.StatusOK, "registered successfully")
}

// Login godoc
// @Summary Вход пользователя
// @Tags auth
// @Accept json
// @Produce json
// @Param input body loginRequest true "Данные для входа"
// @Success 200 {object} map[string]interface{}
// @Router /auth/login [post]
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "invalid request")
		return
	}

	access, refresh, err := h.service.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		if err == errors.ErrUnauthorized {
			response.Error(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		logger.Error("login error", zap.Error(err))
		response.Error(w, http.StatusInternalServerError, "internal error")
		return
	}

	response.JSON(w, http.StatusOK, map[string]string{
		"access_token":  access,
		"refresh_token": refresh,
	})
}

// Refresh godoc
// @Summary Обновление токена
// @Tags auth
// @Accept json
// @Produce json
// @Param input body refreshRequest true "Refresh токен"
// @Success 200 {object} map[string]interface{}
// @Router /auth/refresh [post]
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "invalid request")
		return
	}

	access, err := h.service.Refresh(r.Context(), req.RefreshToken)
	if err != nil {
		response.Error(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}

	response.JSON(w, http.StatusOK, map[string]string{
		"access_token": access,
	})
}

// ResetPassword godoc
// @Summary Восстановление пароля
// @Tags auth
// @Accept json
// @Produce json
// @Param input body resetPasswordRequest true "Email и новый пароль"
// @Success 200 {object} map[string]interface{}
// @Router /auth/reset-password [post]
func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req resetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "invalid request")
		return
	}

	err := h.service.ResetPassword(r.Context(), req.Email, req.NewPassword)
	if err != nil {
		if err == errors.ErrNotFound {
			response.Error(w, http.StatusNotFound, "user not found")
			return
		}
		logger.Error("reset password error", zap.Error(err))
		response.Error(w, http.StatusInternalServerError, "internal error")
		return
	}

	response.JSON(w, http.StatusOK, "password reset successfully")
}