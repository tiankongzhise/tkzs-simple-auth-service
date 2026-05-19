package healthcheck

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/config"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/metrics"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	servicesvc "github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/service"
)

var ErrInvalidInput = errors.New("invalid health check input")

const (
	StatusDegraded = "degraded"
)

type ServiceStore interface {
	ListHealthCheckTargets(ctx context.Context) ([]model.Service, error)
	UpdateHealthStatus(ctx context.Context, id string, status string) error
	CreateHealthCheckLog(ctx context.Context, log *model.HealthCheckLog) error
}

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type Checker struct {
	cfg      *config.Config
	store    ServiceStore
	client   HTTPClient
	failures map[string]int
	now      func() time.Time
}

func NewChecker(cfg *config.Config, store ServiceStore, client HTTPClient) *Checker {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &Checker{
		cfg:      cfg,
		store:    store,
		client:   client,
		failures: map[string]int{},
		now:      time.Now,
	}
}

func (c *Checker) Check(ctx context.Context, target model.Service) (string, error) {
	if target.ID == "" || strings.TrimSpace(target.BaseURL) == "" {
		return "", ErrInvalidInput
	}
	url := strings.TrimRight(target.BaseURL, "/") + normalizePath(target.HealthPath, c.cfg.Health.DefaultPath)
	start := c.now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.client.Do(req)
	latency := c.now().Sub(start)
	httpStatus := 0
	message := ""
	success := false
	if err != nil {
		message = err.Error()
	} else {
		httpStatus = resp.StatusCode
		success = resp.StatusCode >= 200 && resp.StatusCode < 400
		_ = resp.Body.Close()
	}
	status := c.nextStatus(target.ID, success)
	log := &model.HealthCheckLog{
		ServiceID:    target.ID,
		Status:       status,
		HTTPStatus:   httpStatus,
		Latency:      latency,
		ErrorMessage: message,
	}
	if err := c.store.CreateHealthCheckLog(ctx, log); err != nil {
		return "", err
	}
	if target.HealthStatus != status {
		if err := c.store.UpdateHealthStatus(ctx, target.ID, status); err != nil {
			return "", err
		}
	}
	metrics.RecordHealthCheck(target.ID, status)
	return status, nil
}

func (c *Checker) RunOnce(ctx context.Context) error {
	targets, err := c.store.ListHealthCheckTargets(ctx)
	if err != nil {
		return err
	}
	for _, target := range targets {
		if _, err := c.Check(ctx, target); err != nil {
			return err
		}
	}
	return nil
}

func (c *Checker) Start(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(c.cfg.Health.MinIntervalSeconds) * time.Second)
	go func() {
		defer ticker.Stop()
		_ = c.RunOnce(ctx)
		lastChecked := map[string]time.Time{}
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				c.runDue(ctx, now, lastChecked)
			}
		}
	}()
}

func (c *Checker) runDue(ctx context.Context, now time.Time, lastChecked map[string]time.Time) {
	targets, err := c.store.ListHealthCheckTargets(ctx)
	if err != nil {
		return
	}
	for _, target := range targets {
		interval := target.HealthCheckInterval
		if interval <= 0 {
			interval = c.cfg.Health.DefaultIntervalSeconds
		}
		if last, ok := lastChecked[target.ID]; ok && now.Sub(last) < time.Duration(interval)*time.Second {
			continue
		}
		lastChecked[target.ID] = now
		_, _ = c.Check(ctx, target)
	}
}

func (c *Checker) nextStatus(serviceID string, success bool) string {
	if success {
		c.failures[serviceID] = 0
		return servicesvc.HealthHealthy
	}
	c.failures[serviceID]++
	if c.failures[serviceID] >= c.cfg.Health.UnhealthyThreshold {
		return servicesvc.HealthUnhealthy
	}
	return StatusDegraded
}

func normalizePath(path string, fallback string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		path = fallback
	}
	if !strings.HasPrefix(path, "/") {
		return "/" + path
	}
	return path
}
