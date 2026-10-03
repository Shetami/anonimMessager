// Command relay runs the blind message relay.
//
// TLS is terminated either here (-tls-cert/-tls-key) or by a reverse proxy
// that is configured not to write access logs.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/shetami/anonimmessager/server/internal/api"
	"github.com/shetami/anonimmessager/server/internal/store"
)

func main() {
	addr := flag.String("addr", ":8443", "listen address")
	dbPath := flag.String("db", "relay.db", "database file")
	ttl := flag.Duration("ttl", 14*24*time.Hour, "how long undelivered envelopes are kept")
	maxQueue := flag.Int("max-queue", 5000, "max undelivered envelopes per mailbox")
	cert := flag.String("tls-cert", "", "TLS certificate (PEM)")
	key := flag.String("tls-key", "", "TLS private key (PEM)")
	debugAuth := flag.Bool("debug-auth", false, "log why authentication fails (for development)")
	flag.Parse()

	st, err := store.Open(*dbPath, *ttl, *maxQueue)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer st.Close()

	a := api.New(st)
	a.DebugAuth = *debugAuth
	handler := a.Handler()

	srv := &http.Server{
		Addr:              *addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		// Silence per-connection errors: they can contain client addresses.
		ErrorLog: log.New(discard{}, "", 0),
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if _, err := st.PurgeExpired(); err != nil {
					log.Printf("purge: %v", err)
				}
			}
		}
	}()

	go func() {
		var err error
		if *cert != "" {
			err = srv.ListenAndServeTLS(*cert, *key)
		} else {
			log.Printf("WARNING: serving plain HTTP; put a TLS terminator in front")
			err = srv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("serve: %v", err)
		}
	}()
	log.Printf("relay listening on %s", *addr)

	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdown)
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
