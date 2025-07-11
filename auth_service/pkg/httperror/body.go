package httperror

import (
	"encoding/json"
	"net/http"
)

type ErrorResponse struct {
	Error string `json:"error" example:"bad request"`
}

func WriteJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ErrorResponse{Error: message})
}
