// Command note runs note.rima.su: one-time, end-to-end encrypted notes.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"rima.su/note/internal/server"
	"rima.su/note/internal/store"
)

func main() {
	// "note healthcheck" is used by Docker: the runtime image has no shell or curl.
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck())
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	addr := envString("NOTE_ADDR", "127.0.0.1:8080")
	trustProxy := os.Getenv("NOTE_TRUST_PROXY") == "1"
	maxNotes, err := envInt("NOTE_MAX_NOTES", 100_000)
	if err != nil {
		return err
	}
	maxMB, err := envInt("NOTE_MAX_MB", 256)
	if err != nil {
		return err
	}

	st := store.New(maxNotes, maxMB<<20)
	srv, err := server.New(server.Config{TrustProxy: trustProxy}, st)
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

	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				st.Sweep()
				srv.CleanupLimiters()
			}
		}
	}()

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
	err = httpSrv.Shutdown(shutdownCtx)
	st.Wipe()
	slog.Info("stopped, all notes wiped")
	return err
}

func healthcheck() int {
	_, port, err := net.SplitHostPort(envString("NOTE_ADDR", "127.0.0.1:8080"))
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

func envInt(key string, def int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, errors.New("invalid " + key)
	}
	return n, nil
}
