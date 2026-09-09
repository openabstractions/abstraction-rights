package rights

import (
	"errors"
	"fmt"

	job "github.com/openabstractions/abstraction-job/go"
)

// Registration is what an application holds once a person approved it: the
// service it registered with and the secret that designates it there. It is a
// job.Holder, so a job asks this service for awake before it holds and the
// service keeps the platform request on the application's behalf: `rights
// holds` shows the lease owner, kind and id as the reason, and `rights revoke`
// ends the hold the same second.
type Registration struct {
	Client *Client
	Secret string
}

func (r *Registration) Hold(who, why string) (job.Held, error) {
	token, _, err := r.Client.Ask(r.Secret, RightAwake)
	if err != nil {
		return nil, answered(err)
	}
	lease, err := r.Client.Hold(token, who+": "+why)
	if err != nil {
		return nil, answered(err)
	}
	return lease, nil
}

func answered(err error) error {
	if errors.Is(err, ErrNoService) {
		return fmt.Errorf("%w: %v", job.ErrAbsent, err)
	}
	return err
}
