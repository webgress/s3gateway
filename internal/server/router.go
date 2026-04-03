package server

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
)

func (s *Server) newRouter() *mux.Router {
	r := mux.NewRouter()

	// Health check
	r.HandleFunc("/healthz", s.healthCheck).Methods(http.MethodGet)

	// Placeholder — routes will be added in Phase 5/6
	return r
}

func (s *Server) healthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
