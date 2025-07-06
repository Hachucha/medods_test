package unikelongstring

import (
	"crypto/rand"
	"encoding/base64"

	// "medods_test/internal/core/auth/stateless"
	"golang.org/x/crypto/bcrypt"
)

type RefreshTokenHelper struct{}

func NewRefreshTokenHelper() *RefreshTokenHelper {
	return &RefreshTokenHelper{}
}

// Generate создает новый refresh-токен: randomID:userID:tokenPairID (все части в base64, разделитель ':')
func (h *RefreshTokenHelper) Generate() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b), nil
}

func (h *RefreshTokenHelper) GetHash(token string) (string, error) {
	return bcryptHash(token)
}

func bcryptHash(s string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(s), bcrypt.DefaultCost)
	return string(hash), err
}

func splitN(s string, sep byte, n int) []string {
	var res []string
	start := 0
	for i := 0; i < len(s) && len(res) < n-1; i++ {
		if s[i] == sep {
			res = append(res, s[start:i])
			start = i + 1
		}
	}
	res = append(res, s[start:])
	return res
}
