package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/webgress/s3gateway/internal/auth"
)

type Config struct {
	Port        int
	DataDir     string
	Credentials *auth.CredentialStore
	TLSCert     string
	TLSKey      string
	Region      string
}

type Server struct {
	cfg    Config
	httpSrv *http.Server
}

func New(cfg Config) *Server {
	s := &Server{cfg: cfg}
	router := s.newRouter()
	s.httpSrv = &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      router,
		ReadTimeout:  0, // streaming uploads
		WriteTimeout: 0, // streaming downloads
		IdleTimeout:  120 * time.Second,
	}
	return s
}

func (s *Server) Start(ctx context.Context) error {
	errCh := make(chan error, 1)

	go func() {
		slog.Info("starting s3gateway", "port", s.cfg.Port, "data_dir", s.cfg.DataDir)
		var err error
		if s.cfg.TLSCert != "" && s.cfg.TLSKey != "" {
			err = s.httpSrv.ListenAndServeTLS(s.cfg.TLSCert, s.cfg.TLSKey)
		} else {
			err = s.httpSrv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		slog.Info("shutting down server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return s.httpSrv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}
