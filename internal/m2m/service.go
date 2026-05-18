package m2m

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"time"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/config"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/redisx"
)

var (
	ErrAppNotFound      = errors.New("app not found")
	ErrInvalidApp       = errors.New("invalid app")
	ErrInvalidTimestamp = errors.New("invalid timestamp")
	ErrInvalidSignature = errors.New("invalid signature")
	ErrReplayRequest    = errors.New("replay request")
	ErrM2MUnavailable   = errors.New("m2m dependency unavailable")
)

type AppCredential struct {
	AppID          string
	Name           string
	SecretMaterial string
	Status         string
}

type AppStore interface {
	FindAppCredentialByAppID(ctx context.Context, appID string) (*AppCredential, error)
}

type Cache interface {
	KeyBuilder() *redisx.KeyBuilder
	Set(ctx context.Context, key string, value string, ttl time.Duration) error
	Exists(ctx context.Context, key string) (bool, error)
}

type Service struct {
	cfg   *config.Config
	store AppStore
	cache Cache
	now   func() time.Time
}

type VerifyInput struct {
	AppID     string
	Timestamp string
	Sign      string
	Params    map[string]string
}

type VerifyResult struct {
	Allowed bool   `json:"allowed"`
	AppID   string `json:"appId"`
	AppName string `json:"appName"`
}

func NewService(cfg *config.Config, store AppStore, cache Cache) *Service {
	return &Service{
		cfg:   cfg,
		store: store,
		cache: cache,
		now:   time.Now,
	}
}

func (s *Service) SetNow(now func() time.Time) {
	s.now = now
}

func (s *Service) Verify(ctx context.Context, input VerifyInput) (*VerifyResult, error) {
	if input.AppID == "" || input.Timestamp == "" || input.Sign == "" {
		return nil, ErrInvalidApp
	}
	if err := s.validateTimestamp(input.Timestamp); err != nil {
		return nil, err
	}

	app, err := s.store.FindAppCredentialByAppID(ctx, input.AppID)
	if err != nil {
		if errors.Is(err, ErrAppNotFound) {
			return nil, ErrInvalidApp
		}
		return nil, err
	}
	if app.Status != model.StatusEnabled {
		return nil, ErrInvalidApp
	}

	expected := Sign(app.SecretMaterial, input.Timestamp, input.Params)
	if !EqualSign(expected, input.Sign) {
		return nil, ErrInvalidSignature
	}
	if err := s.ensureNonce(ctx, input.AppID, input.Timestamp, input.Sign); err != nil {
		return nil, err
	}
	return &VerifyResult{Allowed: true, AppID: app.AppID, AppName: app.Name}, nil
}

func (s *Service) validateTimestamp(raw string) error {
	timestamp, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return ErrInvalidTimestamp
	}
	requestTime := time.Unix(timestamp, 0)
	skew := s.now().Sub(requestTime)
	if skew < 0 {
		skew = -skew
	}
	if skew > time.Duration(s.cfg.Security.M2MTimestampSkewSeconds)*time.Second {
		return ErrInvalidTimestamp
	}
	return nil
}

func (s *Service) ensureNonce(ctx context.Context, appID string, timestamp string, sign string) error {
	signHash := sha256.Sum256([]byte(sign))
	key, err := s.cache.KeyBuilder().Build("m2m", "nonce", appID, timestamp, hex.EncodeToString(signHash[:]))
	if err != nil {
		return err
	}
	exists, err := s.cache.Exists(ctx, key)
	if err != nil {
		return ErrM2MUnavailable
	}
	if exists {
		return ErrReplayRequest
	}
	if err := s.cache.Set(ctx, key, "1", 60*time.Second); err != nil {
		return ErrM2MUnavailable
	}
	return nil
}
