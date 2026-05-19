package jwtx

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/config"
)

var (
	ErrUnexpectedTokenType = errors.New("unexpected token type")
	ErrUnexpectedIssuer    = errors.New("unexpected issuer")
)

type Manager struct {
	issuer            string
	accessTTL         time.Duration
	refreshTTL        time.Duration
	autoRefreshBefore time.Duration
	privateKey        *rsa.PrivateKey
	publicKey         *rsa.PublicKey
	now               func() time.Time
}

type TokenPair struct {
	AccessToken      string    `json:"accessToken"`
	AccessJTI        string    `json:"accessJti"`
	AccessExpiresAt  time.Time `json:"accessExpiresAt"`
	RefreshToken     string    `json:"refreshToken"`
	RefreshJTI       string    `json:"refreshJti"`
	RefreshExpiresAt time.Time `json:"refreshExpiresAt"`
}

type Subject struct {
	ID          string
	Roles       []string
	Permissions []string
}

func NewManager(cfg config.JWTConfig) (*Manager, error) {
	privateKey, err := LoadPrivateKey(cfg.PrivateKeyPath)
	if err != nil {
		return nil, err
	}
	publicKey, err := LoadPublicKey(cfg.PublicKeyPath)
	if err != nil {
		return nil, err
	}
	return NewManagerWithKeys(cfg, privateKey, publicKey), nil
}

func NewManagerWithKeys(cfg config.JWTConfig, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) *Manager {
	return &Manager{
		issuer:            cfg.Issuer,
		accessTTL:         time.Duration(cfg.AccessExpireMinutes) * time.Minute,
		refreshTTL:        time.Duration(cfg.RefreshExpireHours) * time.Hour,
		autoRefreshBefore: time.Duration(cfg.AutoRefreshBeforeMinutes) * time.Minute,
		privateKey:        privateKey,
		publicKey:         publicKey,
		now:               time.Now,
	}
}

func (m *Manager) SetNow(now func() time.Time) {
	m.now = now
}

func (m *Manager) PublicKey() *rsa.PublicKey {
	return m.publicKey
}

func (m *Manager) IssuePair(subject Subject) (*TokenPair, error) {
	access, err := m.Issue(subject, TokenTypeAccess)
	if err != nil {
		return nil, err
	}
	refresh, err := m.Issue(Subject{ID: subject.ID}, TokenTypeRefresh)
	if err != nil {
		return nil, err
	}
	return &TokenPair{
		AccessToken:      access.Token,
		AccessJTI:        access.JTI,
		AccessExpiresAt:  access.ExpiresAt,
		RefreshToken:     refresh.Token,
		RefreshJTI:       refresh.JTI,
		RefreshExpiresAt: refresh.ExpiresAt,
	}, nil
}

type IssuedToken struct {
	Token     string
	JTI       string
	ExpiresAt time.Time
}

func (m *Manager) Issue(subject Subject, tokenType string) (*IssuedToken, error) {
	ttl, err := m.ttl(tokenType)
	if err != nil {
		return nil, err
	}
	now := m.now().UTC()
	expiresAt := now.Add(ttl)
	jti := uuid.NewString()

	claims := Claims{
		Roles:       subject.Roles,
		Permissions: subject.Permissions,
		Type:        tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   subject.ID,
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(m.privateKey)
	if err != nil {
		return nil, err
	}
	return &IssuedToken{Token: token, JTI: jti, ExpiresAt: expiresAt}, nil
}

func (m *Manager) Parse(tokenString string, expectedType string) (*Claims, error) {
	claims := &Claims{}
	parser := jwt.NewParser(jwt.WithIssuer(m.issuer), jwt.WithTimeFunc(m.now), jwt.WithExpirationRequired())
	token, err := parser.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodRS256 {
			return nil, fmt.Errorf("unexpected signing method %s", token.Header["alg"])
		}
		return m.publicKey, nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, jwt.ErrTokenInvalidClaims
	}
	if claims.Issuer != m.issuer {
		return nil, ErrUnexpectedIssuer
	}
	if claims.Type != expectedType {
		return nil, ErrUnexpectedTokenType
	}
	return claims, nil
}

func (m *Manager) ShouldAutoRefresh(claims *Claims) bool {
	if claims == nil || claims.ExpiresAt == nil {
		return false
	}
	return claims.ExpiresAt.Time.Sub(m.now()) <= m.autoRefreshBefore
}

func (m *Manager) ttl(tokenType string) (time.Duration, error) {
	switch tokenType {
	case TokenTypeAccess:
		return m.accessTTL, nil
	case TokenTypeRefresh:
		return m.refreshTTL, nil
	default:
		return 0, ErrUnexpectedTokenType
	}
}

func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return jwt.ParseRSAPrivateKeyFromPEM(data)
}

func LoadPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return jwt.ParseRSAPublicKeyFromPEM(data)
}
