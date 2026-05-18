package m2m

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/config"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/redisx"
)

func TestVerifySuccessAndReplayRejected(t *testing.T) {
	service, cache := testM2MService(t)
	timestamp := "1779091200"
	sign := Sign("secret", timestamp, map[string]string{"path": "/api/orders"})

	result, err := service.Verify(context.Background(), VerifyInput{
		AppID:     "app00001",
		Timestamp: timestamp,
		Sign:      sign,
		Params:    map[string]string{"path": "/api/orders"},
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !result.Allowed || result.AppID != "app00001" {
		t.Fatalf("result = %#v", result)
	}
	if len(cache.values) != 1 {
		t.Fatalf("nonce values = %#v", cache.values)
	}

	_, err = service.Verify(context.Background(), VerifyInput{
		AppID:     "app00001",
		Timestamp: timestamp,
		Sign:      sign,
		Params:    map[string]string{"path": "/api/orders"},
	})
	if !errors.Is(err, ErrReplayRequest) {
		t.Fatalf("Verify() replay error = %v", err)
	}
}

func TestVerifyRejectsInvalidTimestamp(t *testing.T) {
	service, _ := testM2MService(t)
	_, err := service.Verify(context.Background(), VerifyInput{
		AppID:     "app00001",
		Timestamp: "1779091000",
		Sign:      "abc",
	})
	if !errors.Is(err, ErrInvalidTimestamp) {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestVerifyRejectsInvalidSignature(t *testing.T) {
	service, _ := testM2MService(t)
	_, err := service.Verify(context.Background(), VerifyInput{
		AppID:     "app00001",
		Timestamp: "1779091200",
		Sign:      Sign("wrong", "1779091200", nil),
	})
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Verify() error = %v", err)
	}
}

func testM2MService(t *testing.T) (*Service, *fakeM2MCache) {
	t.Helper()
	cache := newFakeM2MCache(t)
	service := NewService(config.Default(), &fakeAppStore{credential: &AppCredential{
		AppID:          "app00001",
		Name:           "demo app",
		SecretMaterial: "secret",
		Status:         model.StatusEnabled,
	}}, cache)
	service.SetNow(func() time.Time {
		return time.Unix(1779091200, 0)
	})
	return service, cache
}

type fakeAppStore struct {
	credential *AppCredential
}

func (s *fakeAppStore) FindAppCredentialByAppID(_ context.Context, appID string) (*AppCredential, error) {
	if s.credential == nil || s.credential.AppID != appID {
		return nil, ErrAppNotFound
	}
	return s.credential, nil
}

type fakeM2MCache struct {
	keys   *redisx.KeyBuilder
	values map[string]string
	err    error
}

func newFakeM2MCache(t *testing.T) *fakeM2MCache {
	t.Helper()
	keys, err := redisx.NewKeyBuilder("authlimit")
	if err != nil {
		t.Fatalf("NewKeyBuilder() error = %v", err)
	}
	return &fakeM2MCache{keys: keys, values: map[string]string{}}
}

func (c *fakeM2MCache) KeyBuilder() *redisx.KeyBuilder {
	return c.keys
}

func (c *fakeM2MCache) Set(_ context.Context, key string, value string, _ time.Duration) error {
	if c.err != nil {
		return c.err
	}
	c.values[key] = value
	return nil
}

func (c *fakeM2MCache) Exists(_ context.Context, key string) (bool, error) {
	if c.err != nil {
		return false, c.err
	}
	_, ok := c.values[key]
	return ok, nil
}
