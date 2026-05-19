package oidc

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/config"
)

var (
	ErrOIDCDisabled            = errors.New("oidc disabled")
	ErrPublicKeyNotLoaded      = errors.New("oidc public key not loaded")
	ErrUnsupportedGrant        = errors.New("unsupported oidc grant")
	ErrInvalidToken            = errors.New("invalid oidc token")
	ErrTokenServiceUnavailable = errors.New("oidc token service unavailable")
)

type KeyProvider interface {
	PublicKey() *rsa.PublicKey
}

type TokenService interface {
	Refresh(ctx context.Context, refreshToken string) (*TokenResult, error)
	Verify(ctx context.Context, accessToken string) (*VerifyResult, error)
}

type Service struct {
	cfg    *config.Config
	keys   KeyProvider
	tokens TokenService
}

type TokenResult struct {
	TokenType             string `json:"token_type"`
	AccessToken           string `json:"access_token"`
	ExpiresIn             int64  `json:"expires_in"`
	RefreshToken          string `json:"refresh_token,omitempty"`
	RefreshTokenExpiresIn int64  `json:"refresh_token_expires_in,omitempty"`
}

type VerifyResult struct {
	UserID      string
	Roles       []string
	Permissions []string
	ExpiresIn   int64
}

type TokenInput struct {
	GrantType    string
	RefreshToken string
}

type UserInfo struct {
	Subject     string   `json:"sub"`
	Roles       []string `json:"roles,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

type DiscoveryDocument struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserInfoEndpoint                 string   `json:"userinfo_endpoint"`
	JWKSURI                          string   `json:"jwks_uri"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                  []string `json:"scopes_supported"`
	TokenEndpointAuthMethods         []string `json:"token_endpoint_auth_methods_supported"`
	GrantTypesSupported              []string `json:"grant_types_supported"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	KeyType   string `json:"kty"`
	Use       string `json:"use"`
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg"`
	Modulus   string `json:"n"`
	Exponent  string `json:"e"`
}

func NewService(cfg *config.Config, keys KeyProvider, tokens TokenService) *Service {
	return &Service{cfg: cfg, keys: keys, tokens: tokens}
}

func (s *Service) Discovery() (*DiscoveryDocument, error) {
	if !s.cfg.OIDC.Enable {
		return nil, ErrOIDCDisabled
	}
	issuer := s.issuer()
	return &DiscoveryDocument{
		Issuer:                           issuer,
		AuthorizationEndpoint:            issuer + "/oauth2/authorize",
		TokenEndpoint:                    issuer + "/oauth2/token",
		UserInfoEndpoint:                 issuer + "/oauth2/userinfo",
		JWKSURI:                          issuer + "/oauth2/jwks",
		ResponseTypesSupported:           []string{"code"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		ScopesSupported:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethods:         []string{"client_secret_post", "client_secret_basic", "none"},
		GrantTypesSupported:              []string{"authorization_code", "refresh_token"},
	}, nil
}

func (s *Service) JWKS() (*JWKS, error) {
	if !s.cfg.OIDC.Enable {
		return nil, ErrOIDCDisabled
	}
	publicKey := s.keys.PublicKey()
	if publicKey == nil {
		return nil, ErrPublicKeyNotLoaded
	}
	return &JWKS{Keys: []JWK{jwkFromPublicKey(publicKey)}}, nil
}

func (s *Service) Token(ctx context.Context, input TokenInput) (*TokenResult, error) {
	if !s.cfg.OIDC.Enable {
		return nil, ErrOIDCDisabled
	}
	if input.GrantType != "refresh_token" || strings.TrimSpace(input.RefreshToken) == "" {
		return nil, ErrUnsupportedGrant
	}
	if s.tokens == nil {
		return nil, ErrTokenServiceUnavailable
	}
	return s.tokens.Refresh(ctx, input.RefreshToken)
}

func (s *Service) UserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	if !s.cfg.OIDC.Enable {
		return nil, ErrOIDCDisabled
	}
	if strings.TrimSpace(accessToken) == "" {
		return nil, ErrInvalidToken
	}
	if s.tokens == nil {
		return nil, ErrTokenServiceUnavailable
	}
	result, err := s.tokens.Verify(ctx, accessToken)
	if err != nil {
		return nil, err
	}
	return &UserInfo{
		Subject:     result.UserID,
		Roles:       result.Roles,
		Permissions: result.Permissions,
	}, nil
}

func (s *Service) issuer() string {
	issuer := strings.TrimRight(s.cfg.OIDC.Issuer, "/")
	if issuer == "" {
		return strings.TrimRight(s.cfg.Server.Host, "/")
	}
	return issuer
}

func jwkFromPublicKey(key *rsa.PublicKey) JWK {
	return JWK{
		KeyType:   "RSA",
		Use:       "sig",
		KeyID:     keyID(key),
		Algorithm: "RS256",
		Modulus:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		Exponent:  base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

func keyID(key *rsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		sum := sha256.Sum256(key.N.Bytes())
		return base64.RawURLEncoding.EncodeToString(sum[:])
	}
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
