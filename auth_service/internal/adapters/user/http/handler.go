package http

import (
	"encoding/json"

	mw "medods_test/internal/adapters/auth/stateless/http"
	"medods_test/pkg/httperror"
	"net/http"
	"log/slog"
)

type UserHttpHandler struct {
	authMiddleware mw.MiddlewareFactory
	logger *slog.Logger
}

func NewHandler(authMiddleware mw.MiddlewareFactory, logger *slog.Logger) *UserHttpHandler {
	return &UserHttpHandler{
		authMiddleware: authMiddleware,
		logger:         logger,
	}
}

func (h *UserHttpHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/auth/me", h.authMiddleware.Wrap(h.handleMe))
}

// handleMe godoc
// @Summary Получение текущего пользователя
// @Description Возвращает ID пользователя по access токену
// @Description Позжже будет заменена взятием других данных пользователя
// @Tags auth
// @Produce json
// @Success 200 {object} map[string]string
// @Failure 401 {object} httperror.ErrorResponse "unauthorized"
// @Router /auth/me [get]
// @Security Bearer
func (h *UserHttpHandler) handleMe(w http.ResponseWriter, r *http.Request) {

	userID := r.Context().Value("user_id")
	if userID == nil {
		httperror.WriteJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"user_id": userID})
}
