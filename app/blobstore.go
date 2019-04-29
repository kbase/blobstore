package main

import (
	"context"
	"syscall"
	"os/signal"
	"os"
	"time"
	"log"
	"net/http"

	"github.com/kbase/blobstore/service"
)


func main() {
	serv := service.New()
	server := &http.Server{
		Addr:    ":30000",
		Handler: serv,
	}

	go func() {
		// TODO log ip
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

	// TODO handle logging

	// logger.Printf("\nShutdown with timeout: %s\n", timeout)

	if err := hs.Shutdown(ctx); err != nil {
		// logger.Printf("Error: %v\n", err)
	} else {
		// logger.Println("Server stopped")
	}
}