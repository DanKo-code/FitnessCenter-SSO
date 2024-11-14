package grpc

import (
	"SSO/internal/ssoErrors"
	"SSO/internal/usecase"
	logrusCustom "SSO/pkg/logger"
	"context"
	"errors"
	"fmt"
	ssoProtobuf "github.com/DanKo-code/FitnessCenter-Protobuf/gen/FitnessCenter.protobuf.sso"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type SSOgRPC struct {
	ssoProtobuf.UnimplementedSSOServer
	useCase usecase.UseCase
}

func Register(gRPC *grpc.Server, useCase usecase.UseCase) {
	ssoProtobuf.RegisterSSOServer(gRPC, &SSOgRPC{useCase: useCase})
}

func (s SSOgRPC) SignUp(ctx context.Context, suReq *ssoProtobuf.SignUpRequest) (*ssoProtobuf.SignUpResponse, error) {

	logrusCustom.LogWithLocation(logrus.InfoLevel, fmt.Sprintf("Entered SignUp gRPC method with SignUpRequest: %v", suReq))

	suRes, err := s.useCase.SignUp(ctx, suReq)
	if err != nil {

		if errors.Is(err, ssoErrors.UserAlreadyExists) {
			return nil, status.Error(codes.AlreadyExists, err.Error())
		}

		return nil, status.Error(codes.Internal, err.Error())
	}

	return suRes, nil
}

func (s SSOgRPC) SignIn(ctx context.Context, siReq *ssoProtobuf.SignInRequest) (*ssoProtobuf.SignInResponse, error) {

	logrusCustom.LogWithLocation(logrus.InfoLevel, fmt.Sprintf("Entered SignIp gRPC method with SignIpRequest: %v", siReq))

	siRes, err := s.useCase.SignIn(ctx, siReq)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return siRes, nil
}

func (s SSOgRPC) LogOut(ctx context.Context, loReq *ssoProtobuf.LogOutRequest) (*ssoProtobuf.LogOutResponse, error) {

	logrusCustom.LogWithLocation(logrus.InfoLevel, fmt.Sprintf("Entered LogOut gRPC method with LogOutRequest: %v", loReq))

	loRes, err := s.useCase.LogOut(ctx, loReq)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return loRes, nil
}

func (s SSOgRPC) Refresh(ctx context.Context, refReq *ssoProtobuf.RefreshRequest) (*ssoProtobuf.RefreshResponse, error) {

	logrusCustom.LogWithLocation(logrus.InfoLevel, fmt.Sprintf("Entered Refresh gRPC method with RefreshRequest: %v", refReq))

	refRes, err := s.useCase.Refresh(ctx, refReq)
	if err != nil {

		if errors.Is(err, ssoErrors.InvalidFingerPrint) {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}

		return nil, status.Error(codes.Internal, err.Error())
	}

	return refRes, nil
}
