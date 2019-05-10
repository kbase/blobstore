package main

import (
	"fmt"
	"github.com/kbase/blobstore/config"
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kbase/blobstore/service"
	"github.com/jessevdk/go-flags"
)

// note that the contents of this file are tested manually.

const (
	name        = "blobstore"
	version     = "0.1.0"
	shockname   = "Shock"
	shockver    = "0.9.6"
	deprecation = "The id and version fields are deprecated."
)

type options struct {
	// ConfigFile is the path to the config file for the server
	ConfigFile string `long:"conf" required:"true" description:"service config file location"`
}

func main() {
	var opts options
	_, err := flags.Parse(&opts)
	if err != nil {
		os.Exit(1)
	}
	cfg, err := config.New(opts.ConfigFile)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	_ = cfg // TODO NOW pass into service.New
	serv := service.New(service.ServerStaticConf{
		ServerName:          name,
		ServerVersion:       version,
		ID:                  shockname,
		ServerVersionCompat: shockver,
		DeprecationWarning:  deprecation,
	})
	server := &http.Server{
		Addr:    cfg.Host,
		Handler: serv,
	}

	fmt.Printf("Listening on " + cfg.Host + "\n")
	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			fmt.Println(err.Error())
			os.Exit(1)
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

	fmt.Printf("\nShutdown with timeout: %s\n", timeout)

	if err := hs.Shutdown(ctx); err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Println("Server stopped")
	}
}
