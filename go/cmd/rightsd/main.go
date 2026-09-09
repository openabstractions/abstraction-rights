package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"

	asks "github.com/openabstractions/abstraction-asks/go"
	identity "github.com/openabstractions/abstraction-identity"
	logging "github.com/openabstractions/abstraction-logging/go"
	rights "github.com/openabstractions/abstraction-rights/go"
)

func main() {
	endpoint := flag.String("endpoint", rights.DefaultEndpoint(), "where applications connect")
	state := flag.String("state", rights.DefaultStateDir(), "policy.json and admin.secret live here")
	asksAt := flag.String("asks", asks.DefaultEndpoint(), "where the asks service listens; registrations are questions put there")
	flag.Parse()
	slog.SetDefault(slog.New(logging.Default("rightsd")))

	s, err := rights.Start(*endpoint, *state, *asksAt)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	limits := identity.Ceiling()
	slog.Info("listening", "endpoint", *endpoint, "policy", *state, "asks", *asksAt)
	if limits.Bindable {
		slog.Info("registrations show who connected", "how", limits.String())
	} else {
		slog.Info("this machine cannot say which program connects", "why", limits.Binding)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop
	s.Close()
}
