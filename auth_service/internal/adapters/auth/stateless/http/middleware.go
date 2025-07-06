package http

import (
	"context"
	"medods_test/internal/core/auth/stateless"

	"net/http"
)

type MiddlewareFactory struct {
	algohelper AccessTokenAlgoHelper
}

func NewMiddlewareFactory(algohelper AccessTokenAlgoHelper) *MiddlewareFactory {
	return &MiddlewareFactory{algohelper: algohelper}
}

func (h *MiddlewareFactory) Wrap(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if header == "" || len(header) < 8 || header[:7] != "Bearer " {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		tokenStr := header[7:]
		payload, err := h.algohelper.Validate(stateless.AccessToken(tokenStr))
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), "user_id", payload.UserID)
		r = r.WithContext(ctx)
		next(w, r)
	}
}