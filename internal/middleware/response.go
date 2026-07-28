package middleware

import (
	"encoding/json"
	"net/http"
)

func writeBlockError(w http.ResponseWriter, code, message string) {
	writeError(w, http.StatusForbidden, code, message)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}
