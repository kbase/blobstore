package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kbase/blobstore/service"
)

// note that the contents of this file are tested manually.

const (
	name        = "blobstore"
	version     = "0.1.0"
	shockname   = "Shock"
	shockver    = "0.9.6"
	deprecation = "The id and version fields are deprecated."
)

func main() {
	serv := service.New(service.ServerStaticConf{
		ServerName:          name,
		ServerVersion:       version,
		ID:                  shockname,
		ServerVersionCompat: shockver,
		DeprecationWarning:  deprecation,
	})
	server := &http.Server{
		Addr:    "localhost:30000", // TODO get from config
		Handler: serv,
	}

	go func() {
		// TODO LOG ip
		// logger.Printf("Listening on http://0.0.0.0%s\n", hs.Addr)

		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			// TODO is this what we want?
			log.Fatal(err)

		}
	}()

	graceful(server, 5*time.Second)
}

// see https://gist.github.com/peterhellberg/38117e546c217960747aacf689af3dc2
func graceful(hs *http.Server, timeout time.Duration) {
	stop := make(chan os.Signal, 1)

	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// TODO LOG handle logging

	// logger.Printf("\nShutdown with timeout: %s\n", timeout)

	if err := hs.Shutdown(ctx); err != nil {
		// logger.Printf("Error: %v\n", err)
	} else {
		// logger.Println("Server stopped")
	}
}
