package main

import (
	"SSO/internal/server"
	"SSO/pkg/logger"
	"fmt"
	"github.com/joho/godotenv"
	"os"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		logger.FatalLogger.Fatalf(fmt.Sprintf("Error loading .env file: %s", err))
	}

	logger.InfoLogger.Printf("Successfully loaded environment variables")

	appGRPC := server.NewAppGRPC()

	err = appGRPC.Run(os.Getenv("APP_PORT"))
	if err != nil {
		logger.FatalLogger.Printf("Error running server")
	}
}
