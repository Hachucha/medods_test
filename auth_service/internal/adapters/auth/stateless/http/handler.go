package http

import (
	"encoding/json"
	"io"
	"medods_test/internal/core/auth/stateless"

	"medods_test/pkg/httperror"
	"net/http"
)

type Handler struct {
	service           stateless.StatelessAuthService
	middlewareFactory MiddlewareFactory
}

func NewHandler(service stateless.StatelessAuthService, authMiddlewareFactory MiddlewareFactory) *Handler {
	return &Handler{
		service:           service,
		middlewareFactory: authMiddlewareFactory,
	}
}

type AccessTokenAlgoHelper interface {
	Validate(token stateless.AccessToken) (stateless.AccessTokenPayload, error)
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/auth/handleToken", h.handleToken)
	mux.HandleFunc("/auth/refresh", h.handleRefresh)
	mux.HandleFunc("/auth/logout", h.middlewareFactory.Wrap(h.handleLogout))
}

type HandleTokenRequest struct {
	UserID string `json:"user_id"`
}

// handleToken godoc
// @Summary Получение access и refresh токенов
// @Description Возвращает пару токенов по user_id,
// @Description в дальнейшем будет заменена настоящим алгоритмом входа
// @Tags auth
// @Accept json
// @Produce json
// @Param request body HandleTokenRequest true "ID пользователя"
// @Example request "Пример запроса" {
//   "user_id": "123e4567-e89b-12d3-a456-426614174000"
// }
// @Success 200 {object} stateless.TokenPair
// @Failure 401 {object} httperror.ErrorResponse
// @Router /auth/token [post]
func (h *Handler) handleToken(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req HandleTokenRequest
	body, _ := io.ReadAll(r.Body)
	err := json.Unmarshal(body, &req)
	if err != nil || req.UserID == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	cmd := stateless.TestAuthCommand{
		UserId:    stateless.UserID(req.UserID),
		UserAgent: r.UserAgent(),
		IP:        r.RemoteAddr,
	}
	tokens, err := h.service.TestAuthenticateUser(r.Context(), cmd)
	if err != nil {
		httperror.WriteJSONError(w, http.StatusUnauthorized, "internal server error")
		return
	}
	json.NewEncoder(w).Encode(tokens)
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
}

// handleRefresh godoc
// @Summary Обновление пары токенов
// @Description Обновляет токены по старой паре
// @Tags auth
// @Accept json
// @Produce json
//
//	@Param request body RefreshRequest true "Пара токенов"
//
// @Success 200 {object} stateless.TokenPair
// @Failure 400 {object} httperror.ErrorResponse "bad request"
// @Failure 403 {object} httperror.ErrorResponse
// @Router /auth/refresh [post]
// @Example request "Пример пары токенов" {
//   "access_token": "access-token-abc",
//   "refresh_token": "refresh-token-def"
// }
func (h *Handler) handleRefresh(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	body, _ := io.ReadAll(r.Body)
	err := json.Unmarshal(body, &req)
	if err != nil || req.AccessToken == "" || req.RefreshToken == "" {
		httperror.WriteJSONError(w, http.StatusBadRequest, "bad request")
		return
	}
	cmd := stateless.RefreshTokenCommand{
		AccessToken:  stateless.AccessToken(req.AccessToken),
		RefreshToken: stateless.RefreshToken(req.RefreshToken),
		UserAgent:    r.UserAgent(),
		IP:           r.RemoteAddr,
	}
	tokens, err := h.service.RefreshTokens(r.Context(), cmd)
	if err != nil {
		if err == stateless.ErrUserAgentChanged {
			httperror.WriteJSONError(w, http.StatusUnauthorized, "user agent changed")
			return
		}
		w.WriteHeader(http.StatusForbidden)
		return
	}
	json.NewEncoder(w).Encode(tokens)
}

type LogoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// handleLogout godoc
// @Summary Выход пользователя
// @Description Удаляет сессию refresh токена
// @Tags auth
// @Accept json
// @Param request body LogoutRequest true "Refresh токен"
// @Success 200 {string} string "ok"
// @Failure 400 {string} string "bad request"
// @Failure 500 {string} string "internal server error"
// @Router /auth/logout [post]
// @Security Bearer
// @Example request "Пример выхода" {
//   "refresh_token": "refresh-token-def"
// }
func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req LogoutRequest
	body, _ := io.ReadAll(r.Body)
	err := json.Unmarshal(body, &req)
	if err != nil || req.RefreshToken == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	err = h.service.Logout(r.Context(), stateless.RefreshToken(req.RefreshToken), r.Context().Value("user_id").(stateless.UserID))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}
