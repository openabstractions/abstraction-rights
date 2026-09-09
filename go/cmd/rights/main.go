package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	rights "github.com/openabstractions/abstraction-rights/go"
)

const usage = `rights — who may do what on this machine

  rights apps                    every registered application and its rights
  rights grant <app> <right>     rights: ` + "awake" + `
  rights revoke <app> <right>    takes effect now; live holds are dropped
  rights forget <app>
  rights holds                   what is holding the machine awake right now

An application that registers is a question in 'asks pending'; answer it there.
<app> is an id from 'rights apps', or a name if only one has it.
`

func main() {
	endpoint := flag.String("endpoint", rights.DefaultEndpoint(), "where the service listens")
	state := flag.String("state", rights.DefaultStateDir(), "where the service keeps admin.secret")
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(2)
	}

	admin, err := os.ReadFile(filepath.Join(*state, "admin.secret"))
	if err != nil {
		fail("no admin.secret in %s: is rightsd running with -state there?", *state)
	}
	c := &rights.Client{Endpoint: *endpoint, Admin: string(admin)}

	need := func(n int) {
		if len(args) != n+1 {
			flag.Usage()
			os.Exit(2)
		}
	}
	switch args[0] {
	case "apps":
		apps, err := c.Apps()
		check(err)
		if len(apps) == 0 {
			fmt.Println("no applications are registered")
		}
		for _, a := range apps {
			fmt.Printf("%s  %-20s may: %-12s registered %s\n", a.ID, a.Name, list(a.Rights), a.Registered.Local().Format("2006-01-02 15:04"))
			fmt.Printf("      %s\n", seen(a.Seen))
		}
	case "grant":
		need(2)
		check(c.Grant(args[1], args[2]))
	case "revoke":
		need(2)
		check(c.Revoke(args[1], args[2]))
	case "forget":
		need(1)
		check(c.Forget(args[1]))
	case "holds":
		hs, err := c.Holds()
		check(err)
		if len(hs) == 0 {
			fmt.Println("nothing is held")
		}
		for _, h := range hs {
			fmt.Printf("%s  %-20s holds %-8s for %s: %s\n      %s\n", h.App, h.Name, h.Right, ago(h.Since), h.Why, seen(h.Seen))
		}
	default:
		flag.Usage()
		os.Exit(2)
	}
}

func list(rs []string) string {
	if len(rs) == 0 {
		return "nothing"
	}
	return strings.Join(rs, ", ")
}

func seen(s rights.Seen) string {
	if !s.Bound {
		return "who connected is unknown: " + s.Why
	}
	return s.Path + "  " + s.User + "  " + s.Code
}

func ago(t time.Time) string { return time.Since(t).Round(time.Second).String() }

func check(err error) {
	if err != nil {
		fail("%v", err)
	}
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}
