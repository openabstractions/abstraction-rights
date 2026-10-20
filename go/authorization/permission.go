package authorization

import (
	"context"
	"errors"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

// ApplyPermissionAllow pins the trusted typed Book occurrence and commits its
// complete immutable effect. authorize is rechecked inside the policy edit.
type ApplyPermissionAllow func(ctx context.Context, operator wire.Subject, expected, id string, authorize func() error) (wire.SelectorEdit, error)

// UndoPermissionEffect resolves the retained Book effect and removes only the
// still attributable permits. It never accepts an effect supplied by an app.
type UndoPermissionEffect func(ctx context.Context, operator wire.Subject, expected, id string, authorize func() error) (wire.SelectorEdit, error)

func (h *Host) EnablePermissionEffects(apply ApplyPermissionAllow, undo UndoPermissionEffect) error {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	if h.serving || h.ctx.Err() != nil || apply == nil || undo == nil {
		return errors.New("rights: configure typed permission effects before Serve")
	}
	h.permissionAllow, h.permissionUndo = apply, undo
	return nil
}
