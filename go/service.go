package rights

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	asks "github.com/openabstractions/abstraction-asks/go"
	identity "github.com/openabstractions/abstraction-identity"
	"github.com/openabstractions/abstraction-identity/listen"
)

const (
	maxLine       = 64 << 10
	firstLineWait = 10 * time.Second
	approvalWait  = 5 * time.Minute
	registerAsk   = "rights.register"
)

type holder struct {
	Hold
	c       listen.Conn
	release func()
}

type Service struct {
	Endpoint string
	policy   *Policy
	admin    string
	l        listen.Listener
	asks     *asks.Client
	mu       sync.Mutex
	closed   bool
	live     map[listen.Conn]struct{}
	holds    map[*holder]struct{}
	wg       sync.WaitGroup
	awake    func(who, why string) (func(), error)
	// leases writes each wake hold into the resource lease book and reads the
	// holds back from the table (awake_leases.go); nil keeps the listing this
	// service makes itself.
	leases AwakeLeases
}

func Start(endpoint, stateDir, asksEndpoint string) (*Service, error) {
	if err := identity.CanEver(listen.Program); err != nil {
		return nil, fmt.Errorf("rights: every answer here is to a program, and this machine cannot say which one is calling: %w", err)
	}
	policy, err := LoadPolicy(filepath.Join(stateDir, "policy.json"))
	if err != nil {
		return nil, err
	}
	admin := random(32)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(stateDir, "admin.secret"), []byte(admin), 0o600); err != nil {
		return nil, err
	}
	l, err := listen.Listen(endpoint)
	if err != nil {
		return nil, err
	}
	s := &Service{Endpoint: endpoint, policy: policy, admin: hashOf(admin), l: l,
		asks: &asks.Client{Endpoint: asksEndpoint}, live: map[listen.Conn]struct{}{}, holds: map[*holder]struct{}{}, awake: keepAwake}
	go s.loop()
	return s, nil
}

// Close returns once every connection is closed, so a listener started after
// it finds the name free.
func (s *Service) Close() error {
	err := s.l.Close()
	s.mu.Lock()
	s.closed = true
	for c := range s.live {
		c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	return err
}

func (s *Service) loop() {
	for {
		c, err := s.l.Accept()
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			slog.Warn("accept", "err", err)
			continue
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			c.Close()
			continue
		}
		s.live[c] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			s.serve(c)
			s.mu.Lock()
			delete(s.live, c)
			s.mu.Unlock()
		}()
	}
}

func (s *Service) serve(c listen.Conn) {
	kill := time.AfterFunc(firstLineWait, func() { c.Close() })
	k, err := listen.Receive(c, listen.Program, maxLine)
	kill.Stop()
	defer k.Close()
	if err != nil {
		reply(k, Response{Code: CodeCallerRefused, Error: "rights: refused, " + err.Error()})
		return
	}
	var req Request
	if err := json.Unmarshal(k.Frame, &req); err != nil {
		reply(k, Response{Code: CodeInvalidRequest, Error: "not a request: " + err.Error()})
		return
	}
	switch req.Op {
	case OpRegister:
		s.register(k, req)
	case OpHold:
		s.hold(k, req)
	default:
		reply(k, s.answer(req, k.Caller))
	}
}

func reply(c io.Writer, r Response) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = c.Write(append(raw, '\n'))
	return err
}

func (s *Service) answer(req Request, by listen.Seen) Response {
	switch req.Op {
	case OpAsk:
		token, expires, err := s.policy.Ask(req.Secret, req.Right)
		if err != nil {
			return failure(err)
		}
		return Response{Token: token, Expires: expires, Right: req.Right}
	case OpCheck:
		app, right, err := s.policy.Check(req.Token)
		if err != nil {
			return failure(err)
		}
		return Response{App: &app, Right: right}
	case OpApps, OpGrant, OpRevoke, OpForget, OpHolds:
		if subtle.ConstantTimeCompare([]byte(hashOf(req.Admin)), []byte(s.admin)) != 1 {
			return Response{Code: CodeNotAdministrator, Error: "rights: not the policy tool"}
		}
		return s.administer(req, by)
	}
	return Response{Code: CodeUnknownOperation, Error: "rights: unknown op " + req.Op}
}

func (s *Service) administer(req Request, by listen.Seen) Response {
	fail := func(err error) Response { return failure(err) }
	switch req.Op {
	case OpApps:
		return Response{Apps: s.policy.Apps()}
	case OpGrant:
		if err := s.policy.Grant(req.App, req.Right); err != nil {
			return fail(err)
		}
		slog.Info("granted", "app", req.App, "right", req.Right, "by", by.Path)
		return Response{}
	case OpRevoke:
		id, err := s.policy.Revoke(req.App, req.Right)
		if err != nil {
			return fail(err)
		}
		s.drop(func(h *holder) bool { return h.App == id && h.Right == req.Right })
		slog.Info("revoked", "app", req.App, "right", req.Right, "by", by.Path)
		return Response{}
	case OpForget:
		id, err := s.policy.Forget(req.App)
		if err != nil {
			return fail(err)
		}
		s.drop(func(h *holder) bool { return h.App == id })
		slog.Info("forgotten", "app", req.App, "by", by.Path)
		return Response{}
	case OpHolds:
		return Response{Holds: s.listHolds()}
	}
	return Response{}
}

func (s *Service) register(k *listen.Call, req Request) {
	for _, r := range req.Rights {
		if !slices.Contains(Known, r) {
			reply(k, Response{Code: CodeUnknownRight, Error: ErrUnknownRight.Error() + ": " + r})
			return
		}
	}
	if strings.TrimSpace(req.Name) == "" {
		reply(k, Response{Code: CodeInvalidRequest, Error: "rights: an application needs a name"})
		return
	}
	slog.Info("asking", "app", req.Name, "rights", req.Rights, "seen", k.Caller)

	ctx, cancel := context.WithTimeout(context.Background(), approvalWait)
	defer cancel()
	go func() {
		select {
		case <-k.Gone():
			cancel()
		case <-ctx.Done():
		}
	}()
	a, err := s.asks.Await(ctx, question(req, k.Caller))
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		reply(k, Response{Code: CodePending, Error: "rights: nobody answered yet; the question is waiting in 'asks pending', run again once it is answered"})
		return
	case err != nil:
		reply(k, failure(err))
		return
	case !a.Yes && a.Kept:
		reply(k, Response{Code: CodeDeniedPermanently, Error: "rights: refused, and the person asked not to be asked again"})
		return
	case !a.Yes:
		reply(k, Response{Code: CodeDenied, Error: "rights: refused"})
		return
	}
	if err := k.Recheck(); err != nil {
		reply(k, Response{Code: CodeCallerRefused, Error: "rights: refused, " + err.Error()})
		return
	}
	_, secret, err := s.policy.Add(req.Name, req.Rights, k.Caller)
	if err != nil {
		reply(k, failure(err))
		return
	}
	slog.Info("registered", "app", req.Name)
	reply(k, Response{Secret: secret})
}

func question(req Request, seen listen.Seen) asks.Ask {
	return asks.Ask{Asker: req.Name, Key: registerAsk, For: &seen,
		Slots: map[string]string{"rights": strings.Join(req.Rights, ", ")}}
}

func (s *Service) hold(k *listen.Call, req Request) {
	app, right, err := s.policy.Check(req.Token)
	if err != nil {
		reply(k, failure(err))
		return
	}
	// The rule is abstraction.resource/hold on awake; the old word `awake` is
	// the same decision under the name this service has always taken
	// (wire.go Alias, abstraction-resource CONTRACT.md RES-A1).
	action, resource, held := Alias(right)
	if !held {
		reply(k, Response{Code: CodeUnsupportedHold, Error: "rights: " + right + " is not a right that can be held"})
		return
	}
	release, err := s.awake(app.Name, req.Why)
	if err != nil {
		reply(k, Response{Code: CodePlatformRefused, Error: "rights: the platform refused: " + err.Error()})
		return
	}
	h := &holder{Hold: Hold{App: app.ID, Name: app.Name, Right: right, Why: req.Why, Since: time.Now().UTC(), Seen: k.Caller}, c: k, release: release}
	// The hold becomes a row of the resource table's awake resource, so one
	// reader answers who holds the card and who holds the wake. The platform
	// request stays on this connection: that is the half that did not move.
	s.mu.Lock()
	book := s.leases
	s.holds[h] = struct{}{}
	s.mu.Unlock()
	if book != nil {
		lease, end := book.HoldAwake(k.Caller.Path, k.Caller.User, req.Why)
		h.Hold.Lease = lease
		defer end()
	}
	slog.Info("hold", "right", right, "action", action, "resource", resource, "app", app.Name, "why", req.Why, "by", k.Caller.Path)
	if reply(k, Response{App: &app, Right: right}) == nil {
		<-k.Gone()
	}
	s.mu.Lock()
	delete(s.holds, h)
	s.mu.Unlock()
	release()
	slog.Info("released", "right", right, "app", app.Name)
}

func (s *Service) drop(match func(*holder) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for h := range s.holds {
		if match(h) {
			h.c.Close()
		}
	}
}

// listHolds is what holds the machine awake. With a lease book it is the
// table's awake rows, which is what every reader of the wake hold reads; the
// application's name is looked up from the holds this service is carrying,
// because the table names a program and not a registration.
func (s *Service) listHolds() []Hold {
	s.mu.Lock()
	book := s.leases
	live := make([]Hold, 0, len(s.holds))
	for h := range s.holds {
		live = append(live, h.Hold)
	}
	s.mu.Unlock()
	if book == nil {
		sort.Slice(live, func(i, j int) bool { return live[i].Since.Before(live[j].Since) })
		return live
	}
	named := map[string]Hold{}
	for _, h := range live {
		if h.Lease != "" {
			named[h.Lease] = h
		}
	}
	var out []Hold
	for _, row := range book.AwakeHolds() {
		hold := Hold{App: named[row.Lease].App, Name: named[row.Lease].Name, Right: RightAwake,
			Why: row.Why, Since: row.Since, Seen: named[row.Lease].Seen, Lease: row.Lease}
		if hold.Name == "" {
			hold.Name = row.Program
		}
		out = append(out, hold)
	}
	return out
}
