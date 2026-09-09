package rights

import (
	"encoding/json"
	"net"
	"strings"
	"testing"

	identity "github.com/openabstractions/abstraction-identity"
)

type unbound struct{ net.Conn }

func (unbound) Bind() (*identity.Binding, error) { return nil, identity.ErrNoBinding }

func TestEveryEntryPointRefusesACallerTheKernelCannotIdentify(t *testing.T) {
	h := start(t)
	h.s.awake = func(who, why string) (func(), error) { return func() {}, nil }
	secret := registerApproved(t, h, "demo")
	token, _, err := h.app.Ask(secret, RightAwake)
	if err != nil {
		t.Fatal(err)
	}
	admin := h.tool.Admin
	every := []Request{
		{Op: OpRegister, Name: "ghost", Rights: []string{RightAwake}},
		{Op: OpAsk, Secret: secret, Right: RightAwake},
		{Op: OpCheck, Token: token},
		{Op: OpHold, Token: token, Why: "unidentified"},
		{Op: OpApps, Admin: admin},
		{Op: OpGrant, Admin: admin, App: "demo", Right: RightAwake},
		{Op: OpRevoke, Admin: admin, App: "demo", Right: RightAwake},
		{Op: OpForget, Admin: admin, App: "demo"},
		{Op: OpHolds, Admin: admin},
	}
	for _, req := range every {
		resp := serveUnbound(t, h.s, req)
		if !strings.HasPrefix(resp.Error, "rights: refused, ") || !strings.Contains(resp.Error, identity.ErrNoBinding.Error()) {
			t.Errorf("%s with a valid credential and no identity: %+v", req.Op, resp)
		}
	}
	if a, _, err := h.app.Check(token); err != nil || a.Name != "demo" {
		t.Fatalf("the policy was touched by an unidentified caller: %v %v", a, err)
	}
	if holds, _ := h.tool.Holds(); len(holds) != 0 {
		t.Fatalf("an unidentified caller holds: %+v", holds)
	}
	if ps, _ := h.person.Pending(); len(ps) != 0 {
		t.Fatalf("an unidentified registration reached the person: %+v", ps)
	}
}

func serveUnbound(t *testing.T, s *Service, req Request) Response {
	t.Helper()
	server, client := net.Pipe()
	defer client.Close()
	go s.serve(unbound{server})
	raw, _ := json.Marshal(req)
	if _, err := client.Write(append(raw, '\n')); err != nil {
		t.Fatal(err)
	}
	var resp Response
	if err := json.NewDecoder(client).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	return resp
}
