package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/webgress/s3gateway/internal/auth"
	"github.com/webgress/s3gateway/internal/server"
)

func main() {
	port := flag.Int("port", 8333, "HTTP listen port")
	dataDir := flag.String("data-dir", "", "Root directory for object storage (required)")
	credFile := flag.String("credentials", "credentials.json", "Path to credentials JSON")
	tlsCert := flag.String("tls-cert", "", "TLS certificate file (enables HTTPS)")
	tlsKey := flag.String("tls-key", "", "TLS private key file")
	region := flag.String("region", "us-east-1", "AWS region for SigV4")
	logLevel := flag.String("log-level", "info", "Log level: debug, info, warn, error")
	flag.Parse()

	if *dataDir == "" {
		fmt.Fprintln(os.Stderr, "error: -data-dir is required")
		flag.Usage()
		os.Exit(1)
	}

	// Setup logger
	var level slog.Level
	switch *logLevel {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	// Ensure data directory exists
	if err := os.MkdirAll(*dataDir, 0755); err != nil {
		slog.Error("failed to create data directory", "path", *dataDir, "error", err)
		os.Exit(1)
	}

	// Load credentials
	creds, err := auth.LoadCredentials(*credFile)
	if err != nil {
		slog.Error("failed to load credentials", "path", *credFile, "error", err)
		os.Exit(1)
	}

	cfg := server.Config{
		Port:        *port,
		DataDir:     *dataDir,
		Credentials: creds,
		TLSCert:     *tlsCert,
		TLSKey:      *tlsKey,
		Region:      *region,
	}

	srv := server.New(cfg)

	// Graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := srv.Start(ctx); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}
