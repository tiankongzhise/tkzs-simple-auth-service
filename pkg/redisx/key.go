package redisx

import (
	"fmt"
	"regexp"
	"strings"
)

var serviceCodePattern = regexp.MustCompile(`^[a-z0-9]{3,16}$`)

type KeyBuilder struct {
	serviceCode string
}

func NewKeyBuilder(serviceCode string) (*KeyBuilder, error) {
	serviceCode = strings.TrimSpace(serviceCode)
	if !serviceCodePattern.MatchString(serviceCode) {
		return nil, fmt.Errorf("service code must match ^[a-z0-9]{3,16}$")
	}
	return &KeyBuilder{serviceCode: serviceCode}, nil
}

func (b *KeyBuilder) ServiceCode() string {
	return b.serviceCode
}

func (b *KeyBuilder) Prefix() string {
	return b.serviceCode + ":"
}

func (b *KeyBuilder) Build(parts ...string) (string, error) {
	if len(parts) == 0 {
		return "", fmt.Errorf("redis key requires at least one part")
	}
	cleaned := make([]string, 0, len(parts)+1)
	cleaned = append(cleaned, b.serviceCode)
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return "", fmt.Errorf("redis key part cannot be empty")
		}
		if strings.Contains(part, ":") {
			return "", fmt.Errorf("redis key part %q cannot contain ':'", part)
		}
		cleaned = append(cleaned, part)
	}
	return strings.Join(cleaned, ":"), nil
}

func (b *KeyBuilder) MustBuild(parts ...string) string {
	key, err := b.Build(parts...)
	if err != nil {
		panic(err)
	}
	return key
}

func (b *KeyBuilder) IsAllowed(key string) bool {
	return strings.HasPrefix(key, b.Prefix()) && len(key) > len(b.Prefix())
}

func (b *KeyBuilder) Validate(key string) error {
	if !b.IsAllowed(key) {
		return fmt.Errorf("redis key %q must start with %q", key, b.Prefix())
	}
	return nil
}

func (b *KeyBuilder) ValidateKeys(keys ...string) error {
	for _, key := range keys {
		if err := b.Validate(key); err != nil {
			return err
		}
	}
	return nil
}
