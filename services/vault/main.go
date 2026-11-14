// Command vault runs app.rima.su: accounts, keys and access control.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"rima.su/vault/internal/account"
	"rima.su/vault/internal/blobs"
	"rima.su/vault/internal/keys"
	"rima.su/vault/internal/server"
	"rima.su/vault/internal/store"
)

func main() {
	if len(os.Args) == 2 {
		switch os.Args[1] {
		case "healthcheck": // used by Docker: the image has no shell or curl
			os.Exit(healthcheck())
		case "bootstrap-code":
			os.Exit(bootstrapCode())
		}
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

// bootstrapCode prints a fresh one-time code for the first admin and the hash
// to put into VAULT_BOOTSTRAP_HASH. The server never sees the code itself.
func bootstrapCode() int {
	code := make([]byte, account.KeySize)
	_, _ = rand.Read(code)
	enc := base64.RawURLEncoding
	fmt.Printf("code (keep secret, enter it as the invite once): %s\n", enc.EncodeToString(code))
	fmt.Printf("VAULT_BOOTSTRAP_HASH=%s\n", enc.EncodeToString(account.BootstrapHash(code)))
	return 0
}

func run() error {
	addr := envString("VAULT_ADDR", "127.0.0.1:8081")
	dataDir := envString("VAULT_DATA_DIR", "")
	snapDir := os.Getenv("VAULT_SNAPSHOT_DIR")
	trustProxy := os.Getenv("VAULT_TRUST_PROXY") == "1"
	if dataDir == "" {
		return errors.New("VAULT_DATA_DIR is required")
	}

	var bootstrapHash []byte
	if v := os.Getenv("VAULT_BOOTSTRAP_HASH"); v != "" {
		h, err := base64.RawURLEncoding.Strict().DecodeString(v)
		if err != nil || len(h) != 32 {
			return errors.New("invalid VAULT_BOOTSTRAP_HASH")
		}
		bootstrapHash = h
	}

	k, err := keys.Load(dataDir) // also refuses a data dir readable by others
	if err != nil {
		return fmt.Errorf("keys: %w", err)
	}
	if snapDir != "" {
		if err := keys.CheckPrivateDir(snapDir); err != nil {
			return fmt.Errorf("snapshots: %w", err)
		}
	}
	st, err := store.Open(filepath.Join(dataDir, "vault.db"))
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	defer st.Close()
	bs, err := blobs.Open(filepath.Join(dataDir, "blobs"))
	if err != nil {
		return fmt.Errorf("blobs: %w", err)
	}
	defer bs.Close()

	if done, err := st.Bootstrapped(); err != nil {
		return err
	} else if !done && bootstrapHash == nil {
		slog.Warn("no admin yet and VAULT_BOOTSTRAP_HASH is not set: nobody can register")
	}

	srv, err := server.New(server.Config{TrustProxy: trustProxy}, account.New(st, k, bootstrapHash), bs)
	if err != nil {
		return err
	}

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go maintenance(ctx, st, srv, snapDir)

	errCh := make(chan error, 1)
	go func() {
		slog.Info("listening", "addr", addr, "trust_proxy", trustProxy)
		errCh <- httpSrv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return httpSrv.Shutdown(shutdownCtx)
}

// maintenance sweeps expired sessions and invites every minute and writes a
// database snapshot for the host's backup job at start and then daily.
func maintenance(ctx context.Context, st *store.Store, srv *server.Server, snapDir string) {
	snapshot := func() {
		if snapDir == "" {
			return
		}
		if err := st.Snapshot(snapDir); err != nil {
			slog.Error("snapshot failed", "err", err)
		}
	}
	snapshot()
	sweep := time.NewTicker(time.Minute)
	daily := time.NewTicker(24 * time.Hour)
	defer sweep.Stop()
	defer daily.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-sweep.C:
			if _, err := st.Sweep(); err != nil {
				slog.Error("sweep failed", "err", err)
			}
			srv.CleanupLimiters()
		case <-daily.C:
			snapshot()
		}
	}
}

func healthcheck() int {
	_, port, err := net.SplitHostPort(envString("VAULT_ADDR", "127.0.0.1:8081"))
	if err != nil {
		return 1
	}
	c := &http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get("http://127.0.0.1:" + port + "/healthz")
	if err != nil {
		return 1
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func envString(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
