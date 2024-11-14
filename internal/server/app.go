package server

import (
	ssoGRPC "SSO/internal/delivery/grpc"
	"SSO/internal/repository/postgres"
	"SSO/internal/usecase"
	logrusCustom "SSO/pkg/logger"
	"fmt"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"net"
	"os"
	"os/signal"
)

type AppGRPC struct {
	gRPCServer *grpc.Server
	useCase    usecase.UseCase
}

func NewAppGRPC() *AppGRPC {

	logrusCustom.LogWithLocation(logrus.InfoLevel, fmt.Sprintf("Entered NewApp function"))

	db := initDB()

	repository := postgres.NewSSORepository(db)

	useCase := usecase.NewSSOUseCase(repository)

	return &AppGRPC{
		useCase: useCase,
	}
}

func (app *AppGRPC) Run(port string) error {

	logrusCustom.LogWithLocation(logrus.InfoLevel, fmt.Sprintf("Entered Run function"))

	app.gRPCServer = grpc.NewServer()

	ssoGRPC.Register(app.gRPCServer, app.useCase)

	listen, err := net.Listen(os.Getenv("APP_GRPC_PROTOCOL"), ":"+port)
	if err != nil {
		logrusCustom.LogWithLocation(logrus.ErrorLevel, fmt.Sprintf("Failed to listen: %v", err))
		return err
	}

	logrusCustom.LogWithLocation(logrus.InfoLevel, fmt.Sprintf("Starting gRPC server on port %s", port))

	go func() {
		if err = app.gRPCServer.Serve(listen); err != nil {
			logrusCustom.LogWithLocation(logrus.FatalLevel, fmt.Sprintf("Failed to serve: %v", err))
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)

	<-quit

	logrusCustom.LogWithLocation(logrus.InfoLevel, fmt.Sprintf("stopping gRPC server %s", port))
	app.gRPCServer.GracefulStop()

	return nil
}

func initDB() *sqlx.DB {

	logrusCustom.LogWithLocation(logrus.InfoLevel, "Entered initDB function")

	dsn := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
		os.Getenv("DB_SLLMODE"),
	)

	db, err := sqlx.Connect(os.Getenv("DB_DRIVER"), dsn)
	if err != nil {
		logrusCustom.LogWithLocation(logrus.FatalLevel, fmt.Sprintf("Database connection failed: %s", err))
	}

	logrusCustom.LogWithLocation(logrus.InfoLevel, "Successfully connected to db")

	return db
}
