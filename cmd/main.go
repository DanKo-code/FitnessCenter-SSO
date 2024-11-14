package main

import (
	"SSO/internal/server"
	logrusCustom "SSO/pkg/logger"
	"fmt"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
	"os"
)

func main() {
	logrusCustom.InitLogger()

	err := godotenv.Load()
	if err != nil {
		logrusCustom.LogWithLocation(logrus.FatalLevel, fmt.Sprintf("Error loading .env file: %s", err))
	}

	logrusCustom.LogWithLocation(logrus.InfoLevel, "Successfully loaded environment variables")

	appGRPC := server.NewAppGRPC()

	err = appGRPC.Run(os.Getenv("APP_PORT"))
	if err != nil {
		logrusCustom.LogWithLocation(logrus.FatalLevel, "Error running server")
	}
}
