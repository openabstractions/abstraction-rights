package rights

import (
	"path/filepath"
	"testing"
)

func TestRevokeKillsTokensRegrantDoesNotRevive(t *testing.T) {
	p, err := LoadPolicy(filepath.Join(t.TempDir(), "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	app, secret, err := p.Add("demo", []string{RightAwake}, Seen{})
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := p.Ask(secret, RightAwake)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Revoke(app.ID, RightAwake); err != nil {
		t.Fatal(err)
	}
	if err := p.Grant(app.ID, RightAwake); err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.Check(token); err == nil {
		t.Fatal("a token issued before a revoke came back to life on re-grant")
	}
	token, _, err = p.Ask(secret, RightAwake)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Forget(app.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.Check(token); err == nil {
		t.Fatal("a forgotten application's token still checks")
	}
}
