package rights

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"sort"
	"sync"
	"time"

	cas "github.com/openabstractions/abstraction-cas/go"
)

var (
	ErrUnknownApp   = errors.New("rights: no such application")
	ErrUnknownRight = errors.New("rights: no such right")
	ErrNotGranted   = errors.New("rights: not granted")
	ErrBadSecret    = errors.New("rights: secret not recognised")
	ErrBadToken     = errors.New("rights: token not recognised")
)

const tokenLife = time.Hour

type record struct {
	App
	Hash string `json:"hash"`
}

type grant struct {
	app, right string
	expires    time.Time
}

type policy struct {
	Apps []*record `json:"apps"`
}

type Policy struct {
	mu     sync.Mutex
	path   string
	tokens map[string]grant
}

func LoadPolicy(path string) (*Policy, error) {
	p := &Policy{path: path, tokens: map[string]grant{}}
	_, err := p.read()
	return p, err
}

func (p *Policy) read() (policy, error) {
	var f policy
	raw, err := cas.Read(p.path)
	if err != nil || raw == nil {
		return f, err
	}
	return f, json.Unmarshal(raw, &f)
}

func (p *Policy) change(edit func(*policy) error) error {
	return cas.Change(p.path, func(cur []byte) ([]byte, error) {
		var f policy
		if cur != nil {
			if err := json.Unmarshal(cur, &f); err != nil {
				return nil, err
			}
		}
		if err := edit(&f); err != nil {
			return nil, err
		}
		sort.Slice(f.Apps, func(i, j int) bool { return f.Apps[i].ID < f.Apps[j].ID })
		raw, err := json.MarshalIndent(f, "", "  ")
		return append(raw, '\n'), err
	})
}

func (f *policy) find(ref string) (*record, error) {
	if i := slices.IndexFunc(f.Apps, func(r *record) bool { return r.ID == ref }); i >= 0 {
		return f.Apps[i], nil
	}
	var found *record
	for _, r := range f.Apps {
		if r.Name == ref {
			if found != nil {
				return nil, errors.New("rights: more than one application is called " + ref + "; use the id")
			}
			found = r
		}
	}
	if found == nil {
		return nil, ErrUnknownApp
	}
	return found, nil
}

func random(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func hashOf(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])
}

func (p *Policy) Add(name string, rights []string, seen Seen) (App, string, error) {
	for _, r := range rights {
		if !slices.Contains(Known, r) {
			return App{}, "", ErrUnknownRight
		}
	}
	secret := random(32)
	r := &record{
		App:  App{ID: random(4), Name: name, Rights: slices.Clone(rights), Registered: time.Now().UTC(), Seen: seen},
		Hash: hashOf(secret),
	}
	err := p.change(func(f *policy) error {
		f.Apps = append(f.Apps, r)
		return nil
	})
	if err != nil {
		return App{}, "", err
	}
	return r.App, secret, nil
}

func (p *Policy) Apps() []App {
	f, _ := p.read()
	var out []App
	for _, r := range f.Apps {
		out = append(out, r.App)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Registered.Before(out[j].Registered) })
	return out
}

func (p *Policy) Grant(ref, right string) error {
	if !slices.Contains(Known, right) {
		return ErrUnknownRight
	}
	return p.change(func(f *policy) error {
		r, err := f.find(ref)
		if err != nil {
			return err
		}
		if !slices.Contains(r.Rights, right) {
			r.Rights = append(r.Rights, right)
		}
		return nil
	})
}

func (p *Policy) Revoke(ref, right string) (string, error) {
	var id string
	err := p.change(func(f *policy) error {
		r, err := f.find(ref)
		if err != nil {
			return err
		}
		id = r.ID
		r.Rights = slices.DeleteFunc(r.Rights, func(x string) bool { return x == right })
		return nil
	})
	p.purge(func(g grant) bool { return g.app == id && g.right == right })
	return id, err
}

func (p *Policy) purge(match func(grant) bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	maps.DeleteFunc(p.tokens, func(_ string, g grant) bool { return match(g) })
}

func (p *Policy) Forget(ref string) (string, error) {
	var id string
	err := p.change(func(f *policy) error {
		r, err := f.find(ref)
		if err != nil {
			return err
		}
		id = r.ID
		f.Apps = slices.DeleteFunc(f.Apps, func(x *record) bool { return x == r })
		return nil
	})
	p.purge(func(g grant) bool { return g.app == id })
	return id, err
}

func (p *Policy) Ask(secret, right string) (string, time.Time, error) {
	f, err := p.read()
	if err != nil {
		return "", time.Time{}, err
	}
	hash := hashOf(secret)
	i := slices.IndexFunc(f.Apps, func(r *record) bool { return r.Hash == hash })
	if i < 0 {
		return "", time.Time{}, ErrBadSecret
	}
	if !slices.Contains(f.Apps[i].Rights, right) {
		return "", time.Time{}, ErrNotGranted
	}
	t := random(32)
	g := grant{app: f.Apps[i].ID, right: right, expires: time.Now().Add(tokenLife)}
	p.mu.Lock()
	p.tokens[t] = g
	p.mu.Unlock()
	return t, g.expires, nil
}

func (p *Policy) Check(token string) (App, string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	g, ok := p.tokens[token]
	if !ok || time.Now().After(g.expires) {
		delete(p.tokens, token)
		return App{}, "", ErrBadToken
	}
	f, err := p.read()
	if err != nil {
		return App{}, "", err
	}
	i := slices.IndexFunc(f.Apps, func(r *record) bool { return r.ID == g.app })
	if i < 0 || !slices.Contains(f.Apps[i].Rights, g.right) {
		delete(p.tokens, token)
		return App{}, "", ErrNotGranted
	}
	return f.Apps[i].App, g.right, nil
}
