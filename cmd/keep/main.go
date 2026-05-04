// Command keep is the entry point: parse env config, open the DB, run
// migrations, build the server, listen.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/boidushya/keep/internal/config"
	"github.com/boidushya/keep/internal/db"
	"github.com/boidushya/keep/internal/server"
	"github.com/boidushya/keep/internal/ui"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	if err := run(cfg); err != nil {
		log.Fatalf("keep: %v", err)
	}
}

func run(cfg config.Config) error {
	d, err := db.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()

	if err := db.Migrate(context.Background(), d); err != nil {
		return err
	}

	tt, err := ui.New()
	if err != nil {
		return err
	}

	now := time.Now
	deps := server.Deps{
		DB:            d,
		Vault:         server.NewVault(),
		Now:           now,
		PublicURL:     cfg.PublicURL,
		SecureCookies: cfg.SecureCookies,
		Stores:        server.NewStores(d, now),
		Templates:     tt,
	}

	router := server.New(deps)

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("keep listening on %s (public %s db %s)", cfg.Listen, cfg.PublicURL, cfg.DBPath)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
