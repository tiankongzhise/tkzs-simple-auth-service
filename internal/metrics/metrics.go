package metrics

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	httpRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "authlimit_http_requests_total",
		Help: "Total HTTP requests handled by the auth limit service.",
	}, []string{"method", "path", "status"})
	httpRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "authlimit_http_request_duration_seconds",
		Help:    "HTTP request duration in seconds.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "path", "status"})
	limitRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "authlimit_limit_requests_total",
		Help: "Total limit verification results.",
	}, []string{"service_id", "dimension", "allowed"})
	healthChecksTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "authlimit_health_checks_total",
		Help: "Total downstream health check results.",
	}, []string{"service_id", "status"})
)

func Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		status := strconv.Itoa(c.Writer.Status())
		path := c.FullPath()
		if path == "" {
			path = c.Request.URL.Path
		}
		httpRequestsTotal.WithLabelValues(c.Request.Method, path, status).Inc()
		httpRequestDuration.WithLabelValues(c.Request.Method, path, status).Observe(time.Since(start).Seconds())
	}
}

func RecordLimit(serviceID string, dimension string, allowed bool) {
	limitRequestsTotal.WithLabelValues(serviceID, dimension, strconv.FormatBool(allowed)).Inc()
}

func RecordHealthCheck(serviceID string, status string) {
	healthChecksTotal.WithLabelValues(serviceID, status).Inc()
}
