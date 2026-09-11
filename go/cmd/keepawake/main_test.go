package main

import (
	rights "github.com/openabstractions/abstraction-rights/go"
	"testing"
)

func TestRefusalClassification(t *testing.T) {
	for _, tc := range []struct {
		code, message string
		want          bool
	}{
		{rights.CodeBadSecret, "", true},
		{rights.CodeBadSecret, "new diagnostic", true},
		{"", rights.ErrBadSecret.Error(), true},
		{"future_code", rights.ErrBadSecret.Error(), false},
	} {
		err := &rights.RemoteError{Code: tc.code, Message: tc.message}
		if got := refusalIs(err, rights.ErrBadSecret); got != tc.want {
			t.Fatalf("%+v: got %v", tc, got)
		}
	}
}
