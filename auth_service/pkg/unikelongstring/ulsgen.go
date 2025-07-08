package unikelongstring

import (
	"crypto/rand"
	"encoding/base64"

	// "medods_test/internal/core/auth/stateless"
	"golang.org/x/crypto/bcrypt"
)

type ULSHelper struct{}

func NewULSHelper() *ULSHelper {
	return &ULSHelper{}
}

// Generate создает новый refresh-токен: randomID:userID:tokenPairID (все части в base64, разделитель ':')
func (h *ULSHelper) Generate() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b), nil
}

func (h *ULSHelper) GetHash(token string) (string, error) {
	return bcryptHash(token)
}

func bcryptHash(s string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(s), bcrypt.DefaultCost)
	return string(hash), err
}

func (h *ULSHelper) CompareHash(hashFromDb, token string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hashFromDb), []byte(token)) == nil
}
