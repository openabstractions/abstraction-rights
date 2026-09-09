package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	rights "github.com/openabstractions/abstraction-rights/go"
)

const name = "keepawake"

func main() {
	endpoint := flag.String("endpoint", rights.DefaultEndpoint(), "where the rights service listens")
	state := flag.String("state", filepath.Join(rights.DefaultStateDir(), "..", name), "where this program keeps its secret")
	flag.Parse()
	why := strings.Join(flag.Args(), " ")
	if why == "" {
		why = "asked to at the command line"
	}
	c := &rights.Client{Endpoint: *endpoint}
	secretFile := filepath.Join(*state, "secret")

	secret, err := os.ReadFile(secretFile)
	if err != nil {
		secret = []byte(register(c))
		os.MkdirAll(*state, 0o700)
		if err := os.WriteFile(secretFile, secret, 0o600); err != nil {
			fail("%v", err)
		}
	}

	token, _, err := c.Ask(string(secret), rights.RightAwake)
	switch {
	case errors.Is(err, nil):
	case err.Error() == rights.ErrBadSecret.Error():
		os.Remove(secretFile)
		fail("the service no longer knows this program; run it again to register afresh")
	case err.Error() == rights.ErrNotGranted.Error():
		fail("%s is registered but may not hold the machine awake\n  a person can change that:  rights grant %s awake", name, name)
	default:
		fail("%v", err)
	}

	lease, err := c.Hold(token, why)
	if err != nil {
		fail("%v", err)
	}
	fmt.Printf("holding the machine awake: %s\nCtrl-C releases it\n", why)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	select {
	case <-stop:
		lease.Release()
		fmt.Println("released")
	case <-lease.Done():
		fmt.Println("the hold was taken away: a person revoked it, or the service stopped")
		os.Exit(3)
	}
}

func register(c *rights.Client) string {
	fmt.Printf("%s is not registered; asking the service\n  a person has to answer:  asks pending  then  asks answer <id> allow\n", name)
	secret, err := c.Register(name, rights.RightAwake)
	if err != nil {
		fail("%v", err)
	}
	fmt.Println("approved")
	return secret
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}
