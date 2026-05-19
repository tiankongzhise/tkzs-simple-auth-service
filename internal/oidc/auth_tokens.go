package oidc

import (
	"context"
	"errors"
	"time"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/auth"
)

type AuthService interface {
	IssueForUser(ctx context.Context, userID string) (*auth.LoginResult, error)
	Refresh(ctx context.Context, refreshToken string) (*auth.LoginResult, error)
	Verify(ctx context.Context, accessToken string) (*auth.VerifyResult, error)
}

type AuthTokenService struct {
	auth AuthService
	now  func() time.Time
}

func NewAuthTokenService(authService AuthService) *AuthTokenService {
	return &AuthTokenService{auth: authService, now: time.Now}
}

func (s *AuthTokenService) IssueForUser(ctx context.Context, userID string) (*TokenResult, error) {
	result, err := s.auth.IssueForUser(ctx, userID)
	if err != nil {
		return nil, mapAuthError(err)
	}
	return tokenResultFromLogin(s.now(), result), nil
}

func (s *AuthTokenService) Refresh(ctx context.Context, refreshToken string) (*TokenResult, error) {
	result, err := s.auth.Refresh(ctx, refreshToken)
	if err != nil {
		return nil, mapAuthError(err)
	}
	return tokenResultFromLogin(s.now(), result), nil
}

func (s *AuthTokenService) Verify(ctx context.Context, accessToken string) (*VerifyResult, error) {
	result, err := s.auth.Verify(ctx, accessToken)
	if err != nil {
		return nil, mapAuthError(err)
	}
	return &VerifyResult{
		UserID:      result.UserID,
		Roles:       result.Roles,
		Permissions: result.Permissions,
		ExpiresIn:   secondsUntil(s.now(), result.ExpiresAt),
	}, nil
}

func mapAuthError(err error) error {
	switch {
	case errors.Is(err, auth.ErrInvalidToken), errors.Is(err, auth.ErrTokenRevoked):
		return ErrInvalidToken
	case errors.Is(err, auth.ErrAuthUnavailable):
		return ErrTokenServiceUnavailable
	default:
		return err
	}
}

func secondsUntil(now time.Time, expiresAt time.Time) int64 {
	seconds := int64(expiresAt.Sub(now).Seconds())
	if seconds < 0 {
		return 0
	}
	return seconds
}

func tokenResultFromLogin(now time.Time, result *auth.LoginResult) *TokenResult {
	return &TokenResult{
		TokenType:             result.TokenType,
		AccessToken:           result.AccessToken,
		ExpiresIn:             secondsUntil(now, result.AccessTokenExpiresAt),
		RefreshToken:          result.RefreshToken,
		RefreshTokenExpiresIn: secondsUntil(now, result.RefreshTokenExpiresAt),
	}
}
