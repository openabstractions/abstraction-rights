package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/openabstractions/abstraction-identity/listen"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"github.com/openabstractions/abstraction-rights/go/client"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRevisionAdmissionAndUnknownMethodNoFallback(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Program proof unavailable")
	}
	p, _ := policy(t)
	if e := p.EnableRevisionDecisions("receiving-fixture/v1"); e != nil {
		t.Fatal(e)
	}
	c, _ := live(t, p, nil)
	d, e := c.DecideForAtLeastRevisionContext(context.Background(), nativeSubject(t), action, "item", "")
	if e != nil || d.Decision.Outcome != wire.DecisionOutcomeForbidden || d.ObservedRevision != "" {
		t.Fatal(d, e)
	}
	// Emulate the prior authorization@1 method table at its native transport.
	endpoint := listen.Endpoint(fmt.Sprintf("rights-old-method-%d-%d", os.Getpid(), serial.Add(1)))
	l, e := listen.ListenFramed(endpoint, listen.Program)
	if e != nil {
		t.Fatal(e)
	}
	var calls atomic.Int32
	done := make(chan error, 1)
	go func() {
		for {
			conn, e := l.Accept()
			if e != nil {
				done <- nil
				return
			}
			calls.Add(1)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			call, e := listen.ReceiveFramed(ctx, conn, listen.Program, MaxFrameBytes)
			if e == nil {
				var request struct {
					Version int             `json:"version"`
					Service string          `json:"service"`
					Method  string          `json:"method"`
					Payload json.RawMessage `json:"payload"`
				}
				e = json.Unmarshal(call.Frame, &request)
				if e == nil {
					reply, _ := json.Marshal(map[string]any{"version": 1, "service": request.Service, "method": request.Method, "ok": false, "payload": map[string]string{"code": "unknown_method", "message": ""}})
					e = call.Reply(reply)
				}
			}
			if call != nil {
				call.Close()
			}
			conn.Close()
			cancel()
			if e != nil {
				done <- e
				return
			}
		}
	}()
	old := client.New(endpoint)
	_, e = old.DecideForAtLeastRevisionContext(context.Background(), nativeSubject(t), action, "item", "rf1."+strings.Repeat("a", 32)+"."+strings.Repeat("b", 64)+".10")
	var service *wire.ServiceError
	if !errors.As(e, &service) || service.Code != wire.ServiceErrorCodeUnknownMethod {
		t.Errorf("expected unknown_method: %v", e)
	}
	l.Close()
	select {
	case e = <-done:
		if e != nil {
			t.Error(e)
		}
	case <-time.After(2 * time.Second):
		t.Error("old host did not drain")
	}
	if calls.Load() != 1 {
		t.Fatalf("minimum dropped through fallback: %d calls", calls.Load())
	}
}
