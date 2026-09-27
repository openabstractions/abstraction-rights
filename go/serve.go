package rights

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"

	asks "github.com/openabstractions/abstraction-asks/go"
	identity "github.com/openabstractions/abstraction-identity"
	logging "github.com/openabstractions/abstraction-logging/go"
)

const rightsUsage = `Usage: openabstractions serve rights [options]

Holds the granted rights policy, and decides whether a request the runtime
forwards is allowed.

  --endpoint EP   where applications connect (default: the installed
                  runtime's pipe for this service)
  --state DIR     directory holding policy.json and admin.secret (default:
                  this account's state directory)
  --asks EP       where the asks service listens; a registration this
                  service cannot decide is put there as a question (default:
                  the installed runtime's pipe for the asks service)

Exit codes: 0 a clean stop, 1 startup failure, 2 usage error.
`

func isHelp(arg string) bool { return arg == "--help" || arg == "-h" || arg == "help" }

// ErrUsage wraps an error Serve returns for a bad flag or argument, after it
// has already printed rightsUsage. A caller that hosts several capabilities
// tells this apart from a startup failure with errors.Is(err, ErrUsage).
var ErrUsage = errors.New("rights: usage error")

// Serve is this layer's resident half as something another program can call.
// See asks.Serve for why the body left a main. The CLI `rights` has not moved.
func Serve(args []string) error {
	if len(args) > 0 && isHelp(args[0]) {
		_, err := io.WriteString(os.Stdout, rightsUsage)
		return err
	}
	fs := flag.NewFlagSet("rights", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	// rightsUsage already documents every option; the fallback on a genuine
	// parse error prints it once, not a second time as flag.PrintDefaults'
	// own single-dash listing.
	var usageErr error
	fs.Usage = func() { _, usageErr = fmt.Fprint(fs.Output(), rightsUsage) }
	endpoint := fs.String("endpoint", DefaultEndpoint(), "where applications connect")
	state := fs.String("state", DefaultStateDir(), "policy.json and admin.secret live here")
	asksAt := fs.String("asks", asks.DefaultEndpoint(), "where the asks service listens; registrations are questions put there")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return usageErr
		}
		return errors.Join(fmt.Errorf("%w: %v", ErrUsage, err), usageErr)
	}
	// rightsd can start with no logging runtime running. Its own diagnostics go
	// to the explicitly selected environment chain, heard on stderr when nothing
	// is configured [LOG-S8].
	slog.SetDefault(slog.New(logging.LegacyDefault("rights")))

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
