// magpie-oidc is the OIDC sidecar: it signs users in at an OpenID Connect
// provider and keeps each one's magpie gateway key held to the providers
// their groups name. It runs on the same computer and as the same user as
// magpie, so the keys it writes are the ones the gateway reads.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yetone/magpie/oidcsidecar/oidcportal"
)

// version is set at build time, like magpie's.
var version = "dev"

func main() {
	configPath := flag.String("config", os.Getenv("MAGPIE_OIDC_CONFIG"), "YAML config (or $MAGPIE_OIDC_CONFIG)")
	listen := flag.String("listen", "", "address to listen on, overriding the config's")
	check := flag.Bool("check", false, "load the config, discover the provider, and exit")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}
	if *configPath == "" {
		log.Fatal("no config: pass -config PATH or set MAGPIE_OIDC_CONFIG")
	}
	cfg, err := oidcportal.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	state, err := oidcportal.OpenState(cfg.StateFile)
	if err != nil {
		log.Fatalf("state: %v", err)
	}
	policy, err := oidcportal.OpenPolicy(cfg.PolicyFile)
	if err != nil {
		log.Fatalf("policy: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	discover, cancel := context.WithTimeout(ctx, 20*time.Second)
	provider, err := oidcportal.NewProvider(discover, cfg)
	cancel()
	if err != nil {
		log.Fatalf("oidc: %v", err)
	}
	if *check {
		fmt.Printf("ok: issuer %s, %d groups, %d users, %d policies, state %s\n", cfg.Issuer, len(cfg.Groups), len(state.All()), len(policy.List()), cfg.StateFile)
		return
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           oidcportal.NewServer(cfg, state, policy, provider),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Printf("magpie-oidc %s: http://%s, issuer %s", version, cfg.Listen, cfg.Issuer)

	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	case <-ctx.Done():
		log.Print("stopping")
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdown); err != nil {
			log.Printf("shutdown: %v", err)
		}
	}
}
