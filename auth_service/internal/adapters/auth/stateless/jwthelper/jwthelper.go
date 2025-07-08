package jwthelper

import (
	"errors"
	"time"

	"medods_test/internal/core/auth/stateless"

	"github.com/golang-jwt/jwt/v5"
)

type JWTAccessTokenHelper struct {
	Secret []byte
}

func NewJWTAccessTokenHelper(secret string) *JWTAccessTokenHelper {
	return &JWTAccessTokenHelper{Secret: []byte(secret)}
}

func (h *JWTAccessTokenHelper) Generate(payload stateless.AccessTokenPayload) (stateless.AccessToken, error) {
	claims := jwt.MapClaims{
		"user_id":       string(payload.UserID),
		"token_pair_id": string(payload.TokenPairID),
		"role":          string(payload.Role),
		"exp":           time.Now().Add(15 * time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	signed, err := token.SignedString(h.Secret)
	if err != nil {
		return "", err
	}
	return stateless.AccessToken(signed), nil
}

func (h *JWTAccessTokenHelper) Validate(token stateless.AccessToken) (stateless.AccessTokenPayload, error) {
	claims := jwt.MapClaims{}
	t, err := jwt.ParseWithClaims(string(token), claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok || token.Method.Alg() != "HS512" {
			return nil, errors.New("unexpected signing method")
		}
		return h.Secret, nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return stateless.AccessTokenPayload{
				UserID:      stateless.UserID(claims["user_id"].(string)),
				TokenPairID: stateless.TokenPairID(claims["token_pair_id"].(string)),
				Role:        stateless.UserRole(claims["role"].(string)),
			}, stateless.ErrAccessTokenExpired
		}
		return stateless.AccessTokenPayload{}, stateless.ErrAccessTokenInvalid
	}
	if !t.Valid {
		return stateless.AccessTokenPayload{}, stateless.ErrAccessTokenInvalid
	}
	return stateless.AccessTokenPayload{
		UserID:      stateless.UserID(claims["user_id"].(string)),
		TokenPairID: stateless.TokenPairID(claims["token_pair_id"].(string)),
		Role:        stateless.UserRole(claims["role"].(string)),
	}, nil
}
