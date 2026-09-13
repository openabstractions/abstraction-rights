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
	enforcer  AuthorizeEnforcer
	lifecycle sync.Mutex
	serving   bool
	listener  listen.Listener
	owner     string
	policy    *rights.DecisionPolicy
	ctx       context.Context
	cancel    context.CancelFunc
	once      sync.Once
	workers   sync.WaitGroup
	slots     chan struct{}
	OnError   func(error)
	// Assign before Serve. Called when admission stops, before calls drain.
	OnStopped     func()
	operator      AuthorizeOperator
	operatorEpoch string
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
	l, e := listen.Listen(endpoint)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Host{listener: l, owner: owner.Uid, policy: policy, enforcer: enforcer, ctx: ctx, cancel: cancel, slots: make(chan struct{}, 32), operatorEpoch: hex.EncodeToString(epoch[:])}, nil
}
func (h *Host) Close() error {
	var e error
	h.once.Do(func() { h.cancel(); e = h.listener.Close() })
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
		select {
		case h.slots <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		h.workers.Add(1)
		go func() {
			defer h.workers.Done()
			defer func() { <-h.slots }()
			defer conn.Close()
			callCtx, cancel := context.WithTimeout(h.ctx, 5*time.Second)
			defer cancel()
			call, e := listen.ReceiveFramed(callCtx, conn, listen.Program, MaxFrameBytes)
			if call != nil {
				defer call.Close()
			}
			if e == nil {
				var reply []byte
				var service string
				service, e = wire.ServiceName(call.Frame)
				if e == nil {
					switch service {
					case "abstraction.rights/authorization@1":
						reply, e = (&wire.AuthorizationDispatcher{Handler: &receiver{host: h, call: call, ctx: callCtx}}).ExchangeFrame(call.Frame)
					case "abstraction.rights/operator@1":
						reply, e = (&wire.AuthorizationOperatorDispatcher{Handler: &operatorReceiver{receiver{host: h, call: call, ctx: call.WaitContext()}}}).ExchangeFrame(call.Frame)
					default:
						e = errors.New("rights: unsupported service")
					}
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
