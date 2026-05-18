package model

func AllModels() []any {
	return []any{
		&User{},
		&App{},
		&Role{},
		&Permission{},
		&AuthToken{},
		&Service{},
		&RateLimitRule{},
		&Blacklist{},
		&Whitelist{},
		&OIDCClient{},
		&OIDCAuthCode{},
		&OperationLog{},
		&AuthLog{},
		&LimitLog{},
		&HealthCheckLog{},
		&LimitStatistic{},
	}
}
