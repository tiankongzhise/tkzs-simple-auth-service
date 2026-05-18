package model

import "time"

type Service struct {
	BaseModel
	Name                string     `gorm:"size:64;not null;index" json:"name"`
	Code                string     `gorm:"size:64;not null;uniqueIndex" json:"code"`
	OwnerUserID         string     `gorm:"type:char(36);not null;index" json:"ownerUserId"`
	OwnerUser           User       `gorm:"foreignKey:OwnerUserID" json:"ownerUser,omitempty"`
	BaseURL             string     `gorm:"size:255;not null" json:"baseUrl"`
	HealthPath          string     `gorm:"size:128;not null;default:/health" json:"healthPath"`
	Status              string     `gorm:"size:20;not null;default:pending;index" json:"status"`
	Approved            bool       `gorm:"not null;default:false;index" json:"approved"`
	ApprovedBy          *string    `gorm:"type:char(36);index" json:"approvedBy,omitempty"`
	ApprovedAt          *time.Time `json:"approvedAt,omitempty"`
	HealthStatus        string     `gorm:"size:20;not null;default:unknown;index" json:"healthStatus"`
	HealthCheckInterval int        `gorm:"not null;default:30" json:"healthCheckInterval"`
}

func (Service) TableName() string {
	return "services"
}

type RateLimitRule struct {
	BaseModel
	ServiceID     string  `gorm:"type:char(36);not null;uniqueIndex:idx_limit_rule_identity;index" json:"serviceId"`
	Service       Service `gorm:"foreignKey:ServiceID" json:"service,omitempty"`
	Dimension     string  `gorm:"size:32;not null;uniqueIndex:idx_limit_rule_identity" json:"dimension"`
	Granularity   string  `gorm:"size:16;not null;uniqueIndex:idx_limit_rule_identity" json:"granularity"`
	Capacity      int     `gorm:"not null" json:"capacity"`
	RatePerSecond int     `gorm:"not null" json:"ratePerSecond"`
	BlacklistHits int     `gorm:"not null;default:0" json:"blacklistHits"`
	BlockSeconds  int     `gorm:"not null;default:0" json:"blockSeconds"`
	Enabled       bool    `gorm:"not null;default:true;uniqueIndex:idx_limit_rule_identity" json:"enabled"`
	OwnerUserID   string  `gorm:"type:char(36);not null;index" json:"ownerUserId"`
}

func (RateLimitRule) TableName() string {
	return "rate_limit_rules"
}

type Blacklist struct {
	BaseModel
	ServiceID string     `gorm:"type:char(36);not null;uniqueIndex:idx_blacklist_identity;index" json:"serviceId"`
	Service   Service    `gorm:"foreignKey:ServiceID" json:"service,omitempty"`
	Type      string     `gorm:"size:20;not null;uniqueIndex:idx_blacklist_identity" json:"type"`
	Key       string     `gorm:"size:128;not null;uniqueIndex:idx_blacklist_identity" json:"key"`
	Permanent bool       `gorm:"not null;default:false;uniqueIndex:idx_blacklist_identity" json:"permanent"`
	Reason    string     `gorm:"size:255" json:"reason"`
	ExpiresAt *time.Time `gorm:"index" json:"expiresAt,omitempty"`
	CreatedBy string     `gorm:"type:char(36);index" json:"createdBy"`
}

func (Blacklist) TableName() string {
	return "blacklists"
}

type Whitelist struct {
	BaseModel
	ServiceID string     `gorm:"type:char(36);not null;uniqueIndex:idx_whitelist_identity;index" json:"serviceId"`
	Service   Service    `gorm:"foreignKey:ServiceID" json:"service,omitempty"`
	Type      string     `gorm:"size:20;not null;uniqueIndex:idx_whitelist_identity" json:"type"`
	Key       string     `gorm:"size:128;not null;uniqueIndex:idx_whitelist_identity" json:"key"`
	Reason    string     `gorm:"size:255" json:"reason"`
	ExpiresAt *time.Time `gorm:"index" json:"expiresAt,omitempty"`
	CreatedBy string     `gorm:"type:char(36);index" json:"createdBy"`
}

func (Whitelist) TableName() string {
	return "whitelists"
}
