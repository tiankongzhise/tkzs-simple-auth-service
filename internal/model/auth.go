package model

import "time"

type User struct {
	BaseModel
	Username     string     `gorm:"size:20;not null;uniqueIndex" json:"username"`
	PasswordHash string     `gorm:"size:255;not null" json:"-"`
	DisplayName  string     `gorm:"size:64" json:"displayName"`
	Status       string     `gorm:"size:20;not null;default:enabled;index" json:"status"`
	IsSuperAdmin bool       `gorm:"not null;default:false" json:"isSuperAdmin"`
	LastLoginAt  *time.Time `json:"lastLoginAt,omitempty"`
	Roles        []Role     `gorm:"many2many:user_roles;" json:"roles,omitempty"`
}

func (User) TableName() string {
	return "users"
}

type App struct {
	BaseModel
	AppID       string     `gorm:"size:8;not null;uniqueIndex" json:"appId"`
	Name        string     `gorm:"size:64;not null" json:"name"`
	SecretHash  string     `gorm:"size:255;not null" json:"-"`
	OwnerUserID string     `gorm:"type:char(36);not null;index" json:"ownerUserId"`
	OwnerUser   User       `gorm:"foreignKey:OwnerUserID" json:"ownerUser,omitempty"`
	Status      string     `gorm:"size:20;not null;default:enabled;index" json:"status"`
	LastUsedAt  *time.Time `json:"lastUsedAt,omitempty"`
	Roles       []Role     `gorm:"many2many:app_roles;" json:"roles,omitempty"`
}

func (App) TableName() string {
	return "apps"
}

type Role struct {
	BaseModel
	Code        string       `gorm:"size:64;not null;uniqueIndex" json:"code"`
	Name        string       `gorm:"size:64;not null" json:"name"`
	Description string       `gorm:"size:255" json:"description"`
	OwnerUserID *string      `gorm:"type:char(36);index" json:"ownerUserId,omitempty"`
	System      bool         `gorm:"not null;default:false;index" json:"system"`
	Permissions []Permission `gorm:"many2many:role_permissions;" json:"permissions,omitempty"`
}

func (Role) TableName() string {
	return "roles"
}

type Permission struct {
	BaseModel
	Code   string `gorm:"size:64;not null;uniqueIndex" json:"code"`
	Name   string `gorm:"size:64;not null" json:"name"`
	Module string `gorm:"size:32;not null;index" json:"module"`
	Action string `gorm:"size:32;not null" json:"action"`
}

func (Permission) TableName() string {
	return "permissions"
}

type AuthToken struct {
	BaseModel
	UserID    string     `gorm:"type:char(36);not null;index" json:"userId"`
	User      User       `gorm:"foreignKey:UserID" json:"user,omitempty"`
	AppID     *string    `gorm:"type:char(36);index" json:"appId,omitempty"`
	App       *App       `gorm:"foreignKey:AppID" json:"app,omitempty"`
	JTI       string     `gorm:"size:64;not null;uniqueIndex" json:"jti"`
	TokenType string     `gorm:"size:20;not null;index" json:"tokenType"`
	Status    string     `gorm:"size:20;not null;default:active;index" json:"status"`
	ExpiresAt time.Time  `gorm:"not null;index" json:"expiresAt"`
	RevokedAt *time.Time `json:"revokedAt,omitempty"`
}

func (AuthToken) TableName() string {
	return "auth_tokens"
}
