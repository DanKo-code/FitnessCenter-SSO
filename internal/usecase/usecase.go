package usecase

import (
	"SSO/internal/constants"
	"SSO/internal/models"
	"SSO/internal/repository"
	"SSO/internal/ssoErrors"
	"SSO/pkg/logger"
	"context"
	"errors"
	ssoProtobuf "github.com/DanKo-code/FitnessCenter-Protobuf/gen/FitnessCenter.protobuf.sso"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"os"
	"strconv"
	"time"
)

type UseCase interface {
	SignUp(ctx context.Context, suReq *ssoProtobuf.SignUpRequest) (*ssoProtobuf.SignUpResponse, error)
	SignIn(ctx context.Context, siReq *ssoProtobuf.SignInRequest) (*ssoProtobuf.SignInResponse, error)
	LogOut(ctx context.Context, loReq *ssoProtobuf.LogOutRequest) (*ssoProtobuf.LogOutResponse, error)
	Refresh(ctx context.Context, request *ssoProtobuf.RefreshRequest) (*ssoProtobuf.RefreshResponse, error)
}

type SSOUseCase struct {
	ssoRepo repository.SSORepository
}

func NewSSOUseCase(ssoRepo repository.SSORepository) *SSOUseCase {
	return &SSOUseCase{ssoRepo: ssoRepo}
}

type payload struct {
	clientId uuid.UUID
	email    string
	role     string
}

func (ssoUC *SSOUseCase) SignUp(ctx context.Context, suReq *ssoProtobuf.SignUpRequest) (*ssoProtobuf.SignUpResponse, error) {

	user := &models.User{}

	_, err := ssoUC.ssoRepo.GetUserByEmail(suReq.Email)
	if err != nil && !errors.Is(err, ssoErrors.UserNotFound) {
		return nil, err
	} else if err == nil {
		logger.ErrorLogger.Fatalf("Error hGetUserByEmail: %v", ssoErrors.UserAlreadyExists)
		return nil, ssoErrors.UserAlreadyExists
	}

	user.ID = uuid.New()
	hashedPassword, err := HashPassword(suReq.Password)
	if err != nil {
		logger.ErrorLogger.Printf("Error hashing password: %v", err)
		return nil, err
	}
	user.PasswordHash = hashedPassword
	user.Role = constants.ROLES.Client
	user.Name = suReq.Name
	user.Email = suReq.Email
	user.CreatedTime = time.Now()
	user.UpdatedTime = time.Now()

	client, err := ssoUC.ssoRepo.CreateUser(user)
	if err != nil {
		return nil, err
	}

	payload := payload{client.ID, client.Email, client.Role}

	var jwtSecret = []byte(os.Getenv("JWT_SECRET"))
	accessToken, err := GenerateAccessToken(payload, jwtSecret)
	if err != nil {
		logger.ErrorLogger.Printf("Error GenerateAccessToken: %v", err)
		return nil, err
	}

	refreshToken, err := GenerateRefreshToken(client.ID, jwtSecret)
	if err != nil {
		logger.ErrorLogger.Printf("Error GenerateRefreshToken: %v", err)
		return nil, err
	}

	refreshSession := &models.RefreshSessions{}
	refreshSession.Id = uuid.New()
	refreshSession.UserId = client.ID
	refreshSession.RefreshToken = refreshToken
	refreshSession.FingerPrint = suReq.FingerPrint
	refreshSession.CreatedTime = time.Now()
	refreshSession.UpdatedTime = time.Now()

	_, err = ssoUC.ssoRepo.CreateRefreshSession(refreshSession)
	if err != nil {
		logger.ErrorLogger.Printf("Error CreateRefreshSession: %v", err)
		return nil, err
	}

	suRes := &ssoProtobuf.SignUpResponse{}
	suRes.RefreshToken = refreshToken
	suRes.AccessToken = accessToken
	suRes.AccessTokenExpiration = strconv.FormatInt(int64(constants.AccessTokenExpiration), 10)
	suRes.RefreshTokenExpiration = strconv.FormatInt(int64(constants.RefreshTokenExpiration), 10)
	suRes.User = &ssoProtobuf.User{
		Id:          user.ID.String(),
		Name:        user.Name,
		Email:       user.Email,
		Role:        user.Role,
		Photo:       user.Photo,
		CreatedTime: user.CreatedTime.String(),
		UpdatedTime: user.UpdatedTime.String(),
	}

	return suRes, nil
}

func (ssoUC *SSOUseCase) SignIn(ctx context.Context, siReq *ssoProtobuf.SignInRequest) (*ssoProtobuf.SignInResponse, error) {

	user, err := ssoUC.ssoRepo.GetUserByEmail(siReq.Email)
	if err != nil {
		logger.ErrorLogger.Printf("Error GetUserByEmail: %v", err)
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(siReq.Password)); err != nil {
		logger.ErrorLogger.Printf("Error Invalid Password: %v", err)
		return nil, ssoErrors.InvalidPassword
	}

	err = ssoUC.ssoRepo.DeleteRefreshSessionByUserId(user.ID)
	if err != nil && !errors.Is(err, ssoErrors.RefreshSessionNotFound) {
		logger.ErrorLogger.Printf("Error GetUserByEmail: %v", err)
		return nil, err
	}

	payload := payload{user.ID, user.Email, user.Role}
	var jwtSecret = []byte(os.Getenv("JWT_SECRET"))
	accessToken, err := GenerateAccessToken(payload, jwtSecret)
	if err != nil {
		logger.ErrorLogger.Printf("Error GenerateAccessToken: %v", err)
		return nil, err
	}

	refreshToken, err := GenerateRefreshToken(user.ID, jwtSecret)
	if err != nil {
		logger.ErrorLogger.Printf("Error GenerateRefreshToken: %v", err)
		return nil, err
	}

	refreshSession := &models.RefreshSessions{}
	refreshSession.Id = uuid.New()
	refreshSession.UserId = user.ID
	refreshSession.RefreshToken = refreshToken
	refreshSession.FingerPrint = siReq.FingerPrint
	refreshSession.CreatedTime = time.Now()
	refreshSession.UpdatedTime = time.Now()

	_, err = ssoUC.ssoRepo.CreateRefreshSession(refreshSession)
	if err != nil {
		logger.ErrorLogger.Printf("Error CreateRefreshSession: %v", err)
		return nil, err
	}

	siRes := &ssoProtobuf.SignInResponse{}
	siRes.RefreshToken = refreshToken
	siRes.AccessToken = accessToken
	siRes.AccessTokenExpiration = strconv.FormatInt(int64(constants.AccessTokenExpiration), 10)
	siRes.RefreshTokenExpiration = strconv.FormatInt(int64(constants.RefreshTokenExpiration), 10)
	siRes.User = &ssoProtobuf.User{
		Id:          user.ID.String(),
		Name:        user.Name,
		Email:       user.Email,
		Role:        user.Role,
		Photo:       user.Photo,
		CreatedTime: user.CreatedTime.String(),
		UpdatedTime: user.UpdatedTime.String(),
	}

	return siRes, nil
}

func (ssoUC *SSOUseCase) LogOut(ctx context.Context, loReq *ssoProtobuf.LogOutRequest) (*ssoProtobuf.LogOutResponse, error) {

	logOutResponse := &ssoProtobuf.LogOutResponse{}

	err := ssoUC.ssoRepo.DeleteRefreshSessionByRefreshToken(loReq.RefreshToken)
	if err != nil {
		logger.ErrorLogger.Printf("Error LogOut: %v", err)
		logOutResponse.Ok = false
		return logOutResponse, err
	}

	logOutResponse.Ok = true

	return logOutResponse, nil
}

func (ssoUC *SSOUseCase) Refresh(ctx context.Context, refReq *ssoProtobuf.RefreshRequest) (*ssoProtobuf.RefreshResponse, error) {

	token, err := VerifyRefreshToken(refReq.RefreshToken)
	if err != nil {
		logger.ErrorLogger.Printf("Error VerifyRefreshToken: %v", err)
		return nil, err
	}

	refreshSession, err := ssoUC.ssoRepo.GetRefreshSession(refReq.GetRefreshToken())
	if err != nil {
		return nil, err
	}

	if refReq.GetFingerPrint() != refreshSession.FingerPrint {
		logger.ErrorLogger.Printf("Error not valid FingerPrint: %v", refReq)
		return nil, ssoErrors.InvalidFingerPrint
	}

	if err := ssoUC.ssoRepo.DeleteRefreshSessionByRefreshToken(refReq.GetRefreshToken()); err != nil {
		logger.ErrorLogger.Printf("Error DeleteRefreshSessionByRefreshToken: %v", refReq)
		return nil, err
	}

	var userId uuid.UUID
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if id, ok := claims["id"].(string); ok {
			userId, err = uuid.Parse(id)
			if err != nil {
				logger.ErrorLogger.Printf("Error uuid.Parse: %v", err)
				return nil, err
			}
		} else {
			logger.ErrorLogger.Printf("Invalid RefreshToken")
			return nil, ssoErrors.InvalidRefreshToken
		}
	}

	user, err := ssoUC.ssoRepo.GetUserById(userId)
	if err != nil {
		return nil, err
	}

	payload := payload{user.ID, user.Email, user.Role}

	accessTokenNew, err := GenerateAccessToken(payload, []byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		logger.ErrorLogger.Printf("Error GenerateAccessToken: %v", err)
		return nil, err
	}

	refreshTokenNew, err := GenerateRefreshToken(user.ID, []byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		logger.ErrorLogger.Printf("Error GenerateRefreshToken: %v", err)
		return nil, err
	}

	refreshSessionNew := &models.RefreshSessions{}
	refreshSessionNew.Id = uuid.New()
	refreshSessionNew.UserId = user.ID
	refreshSessionNew.RefreshToken = refreshTokenNew
	refreshSessionNew.FingerPrint = refReq.GetFingerPrint()
	refreshSessionNew.CreatedTime = time.Now()
	refreshSessionNew.UpdatedTime = time.Now()

	_, err = ssoUC.ssoRepo.CreateRefreshSession(refreshSessionNew)
	if err != nil {
		return nil, err
	}

	refreshResponse := &ssoProtobuf.RefreshResponse{}
	refreshResponse.RefreshToken = refreshTokenNew
	refreshResponse.AccessToken = accessTokenNew
	refreshResponse.AccessTokenExpiration = strconv.FormatInt(int64(constants.AccessTokenExpiration), 10)
	refreshResponse.RefreshTokenExpiration = strconv.FormatInt(int64(constants.RefreshTokenExpiration), 10)
	refreshResponse.User = &ssoProtobuf.User{
		Id:          user.ID.String(),
		Name:        user.Name,
		Email:       user.Email,
		Role:        user.Role,
		Photo:       user.Photo,
		CreatedTime: user.CreatedTime.String(),
		UpdatedTime: user.UpdatedTime.String(),
	}

	return refreshResponse, nil
}

func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

func GenerateAccessToken(payload payload, jwtSecret []byte) (string, error) {
	claims := jwt.MapClaims{
		"id":    payload.clientId,
		"email": payload.email,
		"role":  payload.role,
		"exp":   time.Now().Add(constants.AccessTokenExpiration).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString(jwtSecret)
}

func GenerateRefreshToken(clientId uuid.UUID, jwtSecret []byte) (string, error) {
	claims := jwt.MapClaims{
		"id":  clientId,
		"exp": time.Now().Add(constants.RefreshTokenExpiration).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString(jwtSecret)
}

func VerifyRefreshToken(refreshToken string) (*jwt.Token, error) {
	secret := []byte(os.Getenv("JWT_SECRET"))

	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		return secret, nil
	})

	if err != nil {
		return nil, err
	}

	return token, nil
}
