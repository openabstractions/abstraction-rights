package main

import (
	"fmt"
	"os"

	rights "github.com/openabstractions/abstraction-rights/go"
)

func main() {
	if err := rights.Serve(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
