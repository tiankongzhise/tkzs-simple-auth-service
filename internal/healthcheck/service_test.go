package healthcheck

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/config"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	servicesvc "github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/service"
)

func TestCheckMarksHealthy(t *testing.T) {
	store := &fakeStore{}
	checker := NewChecker(config.Default(), store, &fakeHTTPClient{status: http.StatusOK})
	checker.now = fixedClock()

	status, err := checker.Check(t.Context(), model.Service{
		BaseModel:    model.BaseModel{ID: "svc-001"},
		BaseURL:      "http://orders.local",
		HealthPath:   "/health",
		HealthStatus: servicesvc.HealthUnknown,
	})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if status != servicesvc.HealthHealthy || store.updatedStatus != servicesvc.HealthHealthy {
		t.Fatalf("status = %q updated = %q", status, store.updatedStatus)
	}
	if store.log.HTTPStatus != http.StatusOK || store.log.Status != servicesvc.HealthHealthy {
		t.Fatalf("log = %#v", store.log)
	}
}

func TestCheckFailureProgressesToUnhealthyAndRecovers(t *testing.T) {
	cfg := config.Default()
	cfg.Health.UnhealthyThreshold = 2
	store := &fakeStore{}
	checker := NewChecker(cfg, store, &fakeHTTPClient{err: errors.New("down")})
	checker.now = fixedClock()
	target := model.Service{
		BaseModel:    model.BaseModel{ID: "svc-001"},
		BaseURL:      "http://orders.local",
		HealthPath:   "/health",
		HealthStatus: servicesvc.HealthHealthy,
	}

	first, err := checker.Check(t.Context(), target)
	if err != nil {
		t.Fatalf("Check() first error = %v", err)
	}
	second, err := checker.Check(t.Context(), target)
	if err != nil {
		t.Fatalf("Check() second error = %v", err)
	}
	if first != StatusDegraded || second != servicesvc.HealthUnhealthy {
		t.Fatalf("first=%q second=%q", first, second)
	}

	checker.client = &fakeHTTPClient{status: http.StatusOK}
	healthy, err := checker.Check(t.Context(), target)
	if err != nil {
		t.Fatalf("Check() recover error = %v", err)
	}
	if healthy != servicesvc.HealthHealthy {
		t.Fatalf("healthy = %q", healthy)
	}
}

func TestRunOnceChecksTargets(t *testing.T) {
	store := &fakeStore{targets: []model.Service{{
		BaseModel:  model.BaseModel{ID: "svc-001"},
		BaseURL:    "http://orders.local",
		HealthPath: "/health",
	}}}
	checker := NewChecker(config.Default(), store, &fakeHTTPClient{status: http.StatusOK})
	checker.now = fixedClock()

	if err := checker.RunOnce(t.Context()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if store.logs != 1 {
		t.Fatalf("logs = %d", store.logs)
	}
}

func fixedClock() func() time.Time {
	now := time.Date(2026, 5, 19, 9, 0, 0, 0, time.UTC)
	return func() time.Time { return now }
}

type fakeStore struct {
	targets       []model.Service
	log           model.HealthCheckLog
	logs          int
	updatedID     string
	updatedStatus string
}

func (s *fakeStore) ListHealthCheckTargets(_ context.Context) ([]model.Service, error) {
	return s.targets, nil
}

func (s *fakeStore) UpdateHealthStatus(_ context.Context, id string, status string) error {
	s.updatedID = id
	s.updatedStatus = status
	return nil
}

func (s *fakeStore) CreateHealthCheckLog(_ context.Context, log *model.HealthCheckLog) error {
	s.log = *log
	s.logs++
	return nil
}

type fakeHTTPClient struct {
	status int
	err    error
}

func (c *fakeHTTPClient) Do(_ *http.Request) (*http.Response, error) {
	if c.err != nil {
		return nil, c.err
	}
	return &http.Response{
		StatusCode: c.status,
		Body:       io.NopCloser(strings.NewReader("ok")),
	}, nil
}
