package audit

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
)

var (
	ErrInvalidInput = errors.New("invalid audit input")
	ErrForbidden    = errors.New("audit access forbidden")
)

const (
	TypeOperation = "operation"
	TypeAuth      = "auth"
	TypeLimit     = "limit"
	TypeHealth    = "health"
)

type Store interface {
	ListOperationLogs(ctx context.Context, filter LogFilter) ([]model.OperationLog, error)
	ListAuthLogs(ctx context.Context, filter LogFilter) ([]model.AuthLog, error)
	ListLimitLogs(ctx context.Context, filter LogFilter) ([]model.LimitLog, error)
	ListHealthLogs(ctx context.Context, filter LogFilter) ([]model.HealthCheckLog, error)
}

type Service struct {
	store Store
}

type Actor struct {
	UserID  string
	IsAdmin bool
}

type LogFilter struct {
	Type      string
	ServiceID string
	Result    string
	ActorID   string
	SubjectID string
	StartAt   *time.Time
	EndAt     *time.Time
	Page      int
	PageSize  int
}

type LogResult struct {
	Type  string `json:"type"`
	Items any    `json:"items"`
	Page  int    `json:"page"`
	Size  int    `json:"pageSize"`
}

func NewService(store Store) *Service {
	return &Service{store: store}
}

func (s *Service) ListLogs(ctx context.Context, actor Actor, filter LogFilter) (*LogResult, error) {
	if actor.UserID == "" {
		return nil, ErrInvalidInput
	}
	filter.Type = strings.TrimSpace(filter.Type)
	if filter.Type == "" {
		filter.Type = TypeOperation
	}
	if !validType(filter.Type) {
		return nil, ErrInvalidInput
	}
	filter.Page, filter.PageSize = normalizePage(filter.Page, filter.PageSize)
	if !actor.IsAdmin {
		filter.ActorID = actor.UserID
		filter.SubjectID = actor.UserID
	}
	switch filter.Type {
	case TypeOperation:
		items, err := s.store.ListOperationLogs(ctx, filter)
		return &LogResult{Type: filter.Type, Items: items, Page: filter.Page, Size: filter.PageSize}, err
	case TypeAuth:
		items, err := s.store.ListAuthLogs(ctx, filter)
		return &LogResult{Type: filter.Type, Items: items, Page: filter.Page, Size: filter.PageSize}, err
	case TypeLimit:
		items, err := s.store.ListLimitLogs(ctx, filter)
		return &LogResult{Type: filter.Type, Items: items, Page: filter.Page, Size: filter.PageSize}, err
	case TypeHealth:
		items, err := s.store.ListHealthLogs(ctx, filter)
		return &LogResult{Type: filter.Type, Items: items, Page: filter.Page, Size: filter.PageSize}, err
	default:
		return nil, ErrInvalidInput
	}
}

func validType(typ string) bool {
	switch typ {
	case TypeOperation, TypeAuth, TypeLimit, TypeHealth:
		return true
	default:
		return false
	}
}

func normalizePage(page int, pageSize int) (int, int) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	return page, pageSize
}
