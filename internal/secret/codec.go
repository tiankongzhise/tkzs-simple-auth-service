package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const encryptedPrefix = "enc:v1:"

type Codec interface {
	EncryptString(plain string) (string, error)
	DecryptString(stored string) (string, error)
}

type AESGCMCodec struct {
	key []byte
}

func NewAESGCMCodec(material []byte, purpose string) (*AESGCMCodec, error) {
	if len(material) == 0 {
		return nil, errors.New("secret material is empty")
	}
	sum := sha256.Sum256(append(append([]byte{}, material...), []byte("\x00"+purpose)...))
	return &AESGCMCodec{key: sum[:]}, nil
}

func NewAESGCMCodecFromFile(path string, purpose string) (*AESGCMCodec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return NewAESGCMCodec(data, purpose)
}

func (c *AESGCMCodec) EncryptString(plain string) (string, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return encryptedPrefix + base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

func (c *AESGCMCodec) DecryptString(stored string) (string, error) {
	if !strings.HasPrefix(stored, encryptedPrefix) {
		return stored, nil
	}
	payload := strings.TrimPrefix(stored, encryptedPrefix)
	data, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(data) < gcm.NonceSize() {
		return "", fmt.Errorf("encrypted secret payload too short")
	}
	nonce := data[:gcm.NonceSize()]
	ciphertext := data[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

type LegacyPassthroughCodec struct{}

func (LegacyPassthroughCodec) EncryptString(plain string) (string, error) {
	return plain, nil
}

func (LegacyPassthroughCodec) DecryptString(stored string) (string, error) {
	return stored, nil
}
