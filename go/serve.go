package rights

import (
	"flag"
	"log/slog"
	"os"
	"os/signal"

	asks "github.com/openabstractions/abstraction-asks/go"
	identity "github.com/openabstractions/abstraction-identity"
	logging "github.com/openabstractions/abstraction-logging/go"
)

// Serve is this layer's resident half as something another program can call.
// See asks.Serve for why the body left a main. The CLI `rights` has not moved.
func Serve(args []string) error {
	fs := flag.NewFlagSet("rights", flag.ContinueOnError)
	endpoint := fs.String("endpoint", DefaultEndpoint(), "where applications connect")
	state := fs.String("state", DefaultStateDir(), "policy.json and admin.secret live here")
	asksAt := fs.String("asks", asks.DefaultEndpoint(), "where the asks service listens; registrations are questions put there")
	if err := fs.Parse(args); err != nil {
		return err
	}
	slog.SetDefault(slog.New(logging.Default("rights")))

	s, err := Start(*endpoint, *state, *asksAt)
	if err != nil {
		return err
	}
	defer s.Close()
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
	return nil
}
