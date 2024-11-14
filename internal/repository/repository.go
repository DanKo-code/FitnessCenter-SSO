package repository

import (
	"SSO/internal/models"
	"github.com/google/uuid"
)

type SSORepository interface {
	GetUserByEmail(email string) (*models.User, error)
	GetUserById(id uuid.UUID) (*models.User, error)
	CreateUser(user *models.User) (*models.User, error)
	CreateRefreshSession(refreshSessions *models.RefreshSessions) (*models.RefreshSessions, error)
	DeleteRefreshSession(refreshToken string) error
	GetRefreshSession(refreshToken string) (*models.RefreshSessions, error)
}
