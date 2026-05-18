package model

import "time"

type OperationLog struct {
	BaseModel
	ActorID    string `gorm:"type:char(36);index" json:"actorId"`
	ActorType  string `gorm:"size:20;not null;index" json:"actorType"`
	Action     string `gorm:"size:64;not null;index" json:"action"`
	Resource   string `gorm:"size:64;not null;index" json:"resource"`
	ResourceID string `gorm:"type:char(36);index" json:"resourceId"`
	IP         string `gorm:"size:64;index" json:"ip"`
	Result     string `gorm:"size:20;not null;index" json:"result"`
	Detail     string `gorm:"type:text" json:"detail"`
}

func (OperationLog) TableName() string {
	return "operation_logs"
}

type AuthLog struct {
	BaseModel
	SubjectID   string `gorm:"type:char(36);index" json:"subjectId"`
	SubjectType string `gorm:"size:20;not null;index" json:"subjectType"`
	Event       string `gorm:"size:64;not null;index" json:"event"`
	IP          string `gorm:"size:64;index" json:"ip"`
	UserAgent   string `gorm:"size:255" json:"userAgent"`
	Result      string `gorm:"size:20;not null;index" json:"result"`
	Reason      string `gorm:"size:255" json:"reason"`
}

func (AuthLog) TableName() string {
	return "auth_logs"
}

type LimitLog struct {
	BaseModel
	ServiceID string `gorm:"type:char(36);not null;index" json:"serviceId"`
	Dimension string `gorm:"size:32;not null;index" json:"dimension"`
	Key       string `gorm:"size:128;not null;index" json:"key"`
	Allowed   bool   `gorm:"not null;index" json:"allowed"`
	Remaining int    `gorm:"not null;default:0" json:"remaining"`
	ResetAt   int64  `gorm:"not null;default:0" json:"resetAt"`
}

func (LimitLog) TableName() string {
	return "limit_logs"
}

type HealthCheckLog struct {
	BaseModel
	ServiceID    string        `gorm:"type:char(36);not null;index" json:"serviceId"`
	Status       string        `gorm:"size:20;not null;index" json:"status"`
	HTTPStatus   int           `gorm:"not null;default:0" json:"httpStatus"`
	Latency      time.Duration `gorm:"not null;default:0" json:"latency"`
	ErrorMessage string        `gorm:"type:text" json:"errorMessage"`
}

func (HealthCheckLog) TableName() string {
	return "health_check_logs"
}

type LimitStatistic struct {
	BaseModel
	ServiceID    string    `gorm:"type:char(36);not null;uniqueIndex:idx_limit_stat_identity;index" json:"serviceId"`
	Dimension    string    `gorm:"size:32;not null;uniqueIndex:idx_limit_stat_identity" json:"dimension"`
	BucketTime   time.Time `gorm:"not null;uniqueIndex:idx_limit_stat_identity;index" json:"bucketTime"`
	TotalCount   int64     `gorm:"not null;default:0" json:"totalCount"`
	BlockedCount int64     `gorm:"not null;default:0" json:"blockedCount"`
}

func (LimitStatistic) TableName() string {
	return "limit_statistics"
}
