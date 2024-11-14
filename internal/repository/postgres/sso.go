package postgres

import (
	"SSO/internal/models"
	"SSO/internal/ssoErrors"
	logrusCustom "SSO/pkg/logger"
	"database/sql"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/sirupsen/logrus"
)

type SSORepository struct {
	db *sqlx.DB
}

func NewSSORepository(db *sqlx.DB) *SSORepository {
	return &SSORepository{db: db}
}

func (ssoRep *SSORepository) GetUserByEmail(email string) (*models.User, error) {
	user := &models.User{}
	err := ssoRep.db.Get(user, `SELECT id, name, email, role, password_hash, photo, created_time, updated_time FROM "user" WHERE email = $1`, email)
	if err != nil {
		logrusCustom.LogWithLocation(logrus.ErrorLevel, fmt.Sprintf("Error GetUserByEmail: %v", err))

		if errors.Is(err, sql.ErrNoRows) {
			return nil, ssoErrors.UserNotFound
		}

		return nil, err
	}

	return user, nil
}

func (ssoRep *SSORepository) GetUserById(id uuid.UUID) (*models.User, error) {
	user := &models.User{}
	err := ssoRep.db.Get(user, `SELECT id, name, email, role, password_hash, photo, created_time, updated_time FROM "user" WHERE id = $1`, id)
	if err != nil {
		logrusCustom.LogWithLocation(logrus.ErrorLevel, fmt.Sprintf("Error GetUserById: %v", err))
		return nil, err
	}

	return user, nil
}

func (ssoRep *SSORepository) CreateUser(user *models.User) (*models.User, error) {
	_, err := ssoRep.db.NamedExec(`
		INSERT INTO "user" (id, name, email, role, password_hash, photo, created_time, updated_time)
		VALUES (:id, :name, :email, :role, :password_hash, :photo, :created_time, :updated_time)`, *user)
	if err != nil {
		logrusCustom.LogWithLocation(logrus.ErrorLevel, fmt.Sprintf("Error CreateUser: %v", err))
		return nil, err
	}

	return user, nil
}

func (ssoRep *SSORepository) CreateRefreshSession(refreshSessions *models.RefreshSessions) (*models.RefreshSessions, error) {
	_, err := ssoRep.db.NamedExec(`
		INSERT INTO refresh_sessions (id, user_id, refresh_token, finger_print, created_time, updated_time)
		VALUES (:id, :user_id, :refresh_token, :finger_print, :created_time, :updated_time)`, *refreshSessions)
	if err != nil {
		logrusCustom.LogWithLocation(logrus.ErrorLevel, fmt.Sprintf("Error CreateRefreshSession: %v", err))
		return nil, err
	}

	return refreshSessions, nil
}

func (ssoRep *SSORepository) DeleteRefreshSession(refreshToken string) error {
	_, err := ssoRep.db.NamedExec(`DELETE FROM refresh_sessions WHERE refresh_token = :RefreshToken`, refreshToken)
	if err != nil {
		logrusCustom.LogWithLocation(logrus.ErrorLevel, fmt.Sprintf("Error DeleteRefreshSession: %v", err))
		return err
	}

	return nil
}

func (ssoRep *SSORepository) GetRefreshSession(refreshToken string) (*models.RefreshSessions, error) {
	refreshSession := &models.RefreshSessions{}
	err := ssoRep.db.Get(refreshSession, `SELECT FROM refresh_sessions WHERE refresh_token = $1`, refreshToken)
	if err != nil {
		logrusCustom.LogWithLocation(logrus.ErrorLevel, fmt.Sprintf("Error GetRefreshSession: %v", err))
		return nil, err
	}

	return refreshSession, nil
}
