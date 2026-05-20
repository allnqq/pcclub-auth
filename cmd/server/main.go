// @title Auth Service API
// @version 1.0
// @description Сервис авторизации ПК клуба
// @host localhost:8081
// @BasePath /
package main

import (
	"net/http"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	httpSwagger "github.com/swaggo/http-swagger"

	_ "github.com/allnqq/pcclub-auth/docs"
	"github.com/allnqq/pcclub-auth/internal/handler"
	"github.com/allnqq/pcclub-auth/internal/repository"
	"github.com/allnqq/pcclub-auth/internal/service"
	"github.com/allnqq/pcclub-shared/pkg/logger"
	"go.uber.org/zap"
)

const (
	dbURL     = "postgres://postgres:4123@localhost:5432/auth_db?sslmode=disable"
	jwtSecret = "supersecretkey"
	port      = ":8081"
)

func main() {
	if err := logger.Init(true); err != nil {
		panic(err)
	}

	db, err := sqlx.Connect("postgres", dbURL)
	if err != nil {
		logger.Fatal("failed to connect to db", zap.Error(err))
	}
	defer db.Close()

	userRepo := repository.NewUserRepository(db)
	tokenRepo := repository.NewTokenRepository(db)
	authService := service.NewAuthService(userRepo, tokenRepo, jwtSecret)
	authHandler := handler.NewAuthHandler(authService)

	mux := http.NewServeMux()
	mux.HandleFunc("/auth/register", authHandler.Register)
	mux.HandleFunc("/auth/login", authHandler.Login)
	mux.HandleFunc("/auth/refresh", authHandler.Refresh)
	mux.HandleFunc("/auth/reset-password", authHandler.ResetPassword)
	mux.HandleFunc("/swagger/", httpSwagger.WrapHandler)

	logger.Info("auth-service started", zap.String("port", port))
	if err := http.ListenAndServe(port, mux); err != nil {
		logger.Fatal("server error", zap.Error(err))
	}
}