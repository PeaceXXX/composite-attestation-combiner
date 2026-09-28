// Command server runs the composite attestation + key-release service.
//
// Configuration (environment):
//
//	KMS_MASTER_KEY        64 hex chars (32 bytes) — required
//	KEYS_FILE             path to wrapped keys JSON (default data/keys.json)
//	REFERENCE_MANIFEST    path to golden reference JSON (default data/reference-manifest.json)
//	FRESHNESS_SECONDS     evidence freshness window (default 300)
//	LISTEN_ADDR           listen address (default :8080)
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/PeaceXXX/composite-attestation-combiner/internal/keyrelease"
	"github.com/PeaceXXX/composite-attestation-combiner/internal/policy"
	"github.com/PeaceXXX/composite-attestation-combiner/internal/reference"
	"github.com/PeaceXXX/composite-attestation-combiner/internal/server"
	"github.com/PeaceXXX/composite-attestation-combiner/internal/verifier"
)

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	master, err := keyrelease.MasterKeyFromEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(1)
	}
	manifest, err := reference.Load(getenv("REFERENCE_MANIFEST", "data/reference-manifest.json"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(1)
	}
	kms, err := keyrelease.NewFromFile(getenv("KEYS_FILE", "data/keys.json"), master)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(1)
	}
	freshness := time.Duration(manifest.FreshnessWindowSeconds) * time.Second
	if v := os.Getenv("FRESHNESS_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			freshness = time.Duration(n) * time.Second
		}
	}
	svc := &server.Service{
		Combiner: policy.Combiner{
			CPU:             verifier.CPUVerifier{Ref: &manifest.CPU},
			GPU:             verifier.GPUVerifier{Ref: &manifest.GPU},
			FreshnessWindow: freshness,
		},
		KMS: kms,
	}
	addr := getenv("LISTEN_ADDR", ":8080")
	srv := &http.Server{
		Addr:              addr,
		Handler:           svc.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		fmt.Printf("composite-attestation-combiner listening on %s (freshness=%s)\n", addr, freshness)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintln(os.Stderr, "serve:", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	fmt.Fprintln(os.Stderr, "shutting down...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		fmt.Fprintln(os.Stderr, "shutdown:", err)
		os.Exit(1)
	}
}
