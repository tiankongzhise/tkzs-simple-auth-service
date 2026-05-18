package model

import "time"

type OIDCClient struct {
	BaseModel
	ClientID     string `gorm:"size:64;not null;uniqueIndex" json:"clientId"`
	ClientSecret string `gorm:"size:255;not null" json:"-"`
	Name         string `gorm:"size:64;not null" json:"name"`
	RedirectURI  string `gorm:"size:512;not null" json:"redirectUri"`
	OwnerUserID  string `gorm:"type:char(36);not null;index" json:"ownerUserId"`
	Status       string `gorm:"size:20;not null;default:enabled;index" json:"status"`
}

func (OIDCClient) TableName() string {
	return "oidc_clients"
}

type OIDCAuthCode struct {
	BaseModel
	Code        string    `gorm:"size:128;not null;uniqueIndex" json:"code"`
	ClientID    string    `gorm:"size:64;not null;index" json:"clientId"`
	UserID      string    `gorm:"type:char(36);not null;index" json:"userId"`
	RedirectURI string    `gorm:"size:512;not null" json:"redirectUri"`
	Scope       string    `gorm:"size:255" json:"scope"`
	ExpiresAt   time.Time `gorm:"not null;index" json:"expiresAt"`
	Used        bool      `gorm:"not null;default:false;index" json:"used"`
}

func (OIDCAuthCode) TableName() string {
	return "oidc_auth_codes"
}
