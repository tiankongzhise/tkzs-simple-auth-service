package m2m

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"sort"
	"strings"
)

func CanonicalString(secret string, timestamp string, params map[string]string) string {
	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	parts := []string{secret, timestamp}
	for _, key := range keys {
		parts = append(parts, key+"="+params[key])
	}
	return strings.Join(parts, "&")
}

func Sign(secret string, timestamp string, params map[string]string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(CanonicalString(secret, timestamp, params)))
	return hex.EncodeToString(mac.Sum(nil))
}

func EqualSign(expected string, actual string) bool {
	expectedBytes, err := hex.DecodeString(expected)
	if err != nil {
		return false
	}
	actualBytes, err := hex.DecodeString(actual)
	if err != nil {
		return false
	}
	return hmac.Equal(expectedBytes, actualBytes)
}

func ParamsFromValues(values url.Values) map[string]string {
	params := make(map[string]string, len(values))
	for key, value := range values {
		if len(value) == 0 {
			continue
		}
		params[key] = value[0]
	}
	return params
}
