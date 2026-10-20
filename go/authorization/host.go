// Package authorization hosts the configured rights decision point.
package authorization

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	identity "github.com/openabstractions/abstraction-identity"
	"github.com/openabstractions/abstraction-identity/listen"
	rights "github.com/openabstractions/abstraction-rights/go"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	watch "github.com/openabstractions/abstraction-watch/go"
	"os/user"
	"sync"
	"time"
)

const MaxFrameBytes = 1 << 20

// AuthorizeEnforcer explicitly trusts this receiving peer to assert subjects for
// the exact action/resource. Nil refuses all DecideFor calls.
// It must honor ctx and be safe for concurrent calls.
type AuthorizeEnforcer func(context.Context, *identity.Peer, string, string) bool

type Host struct {
	enforcer         AuthorizeEnforcer
	selectorEnforcer AuthorizeSelectorEnforcer
	lifecycle        sync.Mutex
	serving          bool
	listener         listen.Listener
	owner            string
	policy           *rights.DecisionPolicy
	ctx              context.Context
	cancel           context.CancelFunc
	once             sync.Once
	workers          sync.WaitGroup
	slots            listen.CallAdmission
	OnError          func(error)
	// Assign before Serve. Called when admission stops, before calls drain.
	OnStopped         func()
	operator          AuthorizeOperator
	firstUseAllow     ApplyFirstUseAllow
	permissionAllow   ApplyPermissionAllow
	permissionUndo    UndoPermissionEffect
	changes           OperatorChanges
	operatorEpoch     string
	observationGate   *watch.Gate
	removeObservation func()
}

// Listen requires explicit provider configuration. It performs no discovery.
func Listen(endpoint string, policy *rights.DecisionPolicy, enforcer AuthorizeEnforcer) (*Host, error) {
	if policy == nil {
		return nil, errors.New("rights: configured decision policy required")
	}
	owner, e := user.Current()
	if e != nil {
		return nil, e
	}
	if owner.Uid == "" {
		return nil, errors.New("rights: service principal unavailable")
	}
	var epoch [16]byte
	if _, e = rand.Read(epoch[:]); e != nil {
		return nil, e
	}
	l, e := listen.ListenFramed(endpoint, listen.Program)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithCancel(context.Background())
	gate := watch.NewGate(16) // Leave connection slots for reads and edits.
	return &Host{listener: listen.Sessions(l, listen.SessionOptions{MaxSessions: 32}), owner: owner.Uid, policy: policy, enforcer: enforcer, ctx: ctx, cancel: cancel, slots: listen.NewCallAdmission(32), operatorEpoch: hex.EncodeToString(epoch[:]), observationGate: gate, removeObservation: policy.OnChange(gate.Advance)}, nil
}
func (h *Host) Close() error {
	var e error
	h.once.Do(func() {
		h.cancel()
		h.removeObservation()
		h.observationGate.Fail(errors.New("rights: observation closed"))
		e = h.listener.Close()
	})
	return e
}
func (h *Host) Serve(ctx context.Context) error {
	h.lifecycle.Lock()
	if h.serving {
		h.lifecycle.Unlock()
		return errors.New("rights: host already served")
	}
	h.serving = true
	h.lifecycle.Unlock()
	stop := context.AfterFunc(ctx, func() { h.Close() })
	defer stop()
	defer h.workers.Wait()
	defer func() {
		if h.OnStopped != nil {
			h.OnStopped()
		}
	}()
	defer h.Close()
	for {
		conn, e := h.listener.Accept()
		if e != nil {
			if ctx.Err() != nil || h.ctx.Err() != nil {
				return nil
			}
			return e
		}
		release, admitted := h.slots.Take(conn)
		if !admitted {
			continue
		}
		h.workers.Add(1)
		go func() {
			defer h.workers.Done()
			defer release()
			defer conn.Close()
			// Only decoded ObservePolicy may use the long call. Ordinary framing,
			// methods and replies retain the existing five-second deadline.
			callCtx, cancel := context.WithTimeout(h.ctx, 35*time.Second)
			defer cancel()
			legacyCtx, cancelLegacy := context.WithTimeout(callCtx, 5*time.Second)
			defer cancelLegacy()
			stopLegacy := context.AfterFunc(legacyCtx, cancel)
			defer stopLegacy()
			call, e := listen.ReceiveFramed(callCtx, conn, listen.Program, MaxFrameBytes)
			if call != nil {
				defer call.Close()
			}
			if e == nil {
				deadline, _ := legacyCtx.Deadline()
				ordinaryCtx, finishOrdinary := context.WithDeadline(call.WaitContext(), deadline)
				defer finishOrdinary()
				longCall := false
				operator := operatorReceiver{
					receiver: receiver{host: h, call: call, ctx: ordinaryCtx},
					observationContext: func() context.Context {
						if legacyCtx.Err() != nil || !time.Now().Before(deadline) || !stopLegacy() {
							cancel() // A fired guard can never be revived.
						} else {
							longCall = true
						}
						return call.WaitContext()
					},
				}
				var reply []byte
				reply, e = wire.ServeEndpoint(call.Frame, "openabstractions", "",
					&wire.AuthorizationDispatcher{Handler: &receiver{host: h, call: call, ctx: ordinaryCtx}},
					&wire.AuthorizationOperatorDispatcher{Handler: &operator},
					&wire.SelectorAuthorizationDispatcher{Handler: &selectorReceiver{receiver{host: h, call: call, ctx: ordinaryCtx}}},
					&wire.SelectorAuthorizationOperatorDispatcher{Handler: &selectorOperatorReceiver{operator}})
				if !longCall && (legacyCtx.Err() != nil || !time.Now().Before(deadline)) {
					cancel()
				}
				if e == nil {
					e = call.Reply(reply)
				}
			}
			if e != nil && h.OnError != nil && h.ctx.Err() == nil {
				h.OnError(e)
			}
		}()
	}
}
