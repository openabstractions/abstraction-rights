package authorization

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"strconv"
	"strings"
	"unicode/utf8"
)

func descriptionRefusal(outcome wire.PolicyPageOutcome) wire.DescriptionPage {
	return wire.DescriptionPage{Outcome: outcome, Actions: []wire.DescribedAction{}}
}
func (r *receiver) descriptionCaller() (wire.Subject, error) {
	s, _, err := r.caller()
	if err != nil || s.Account != r.host.owner {
		return wire.Subject{}, ErrOperatorForbidden
	}
	if err = r.ctx.Err(); err != nil {
		return wire.Subject{}, err
	}
	return s, nil
}
func (r *receiver) ListActionDescriptions(cursor string, limit int64) (wire.DescriptionPage, error) {
	subject, err := r.descriptionCaller()
	if err != nil {
		return descriptionRefusal(operatorPageError(err)), nil
	}
	if limit < 1 || limit > 64 || len(cursor) > 256 || !utf8.ValidString(cursor) {
		return descriptionRefusal(wire.PolicyPageOutcomeInvalid), nil
	}
	revision, actions, err := r.host.policy.DescriptionSnapshot(r.ctx)
	if err != nil {
		return descriptionRefusal(wire.PolicyPageOutcomeUnavailable), nil
	}
	scope, err := json.Marshal(subject)
	if err != nil {
		return descriptionRefusal(wire.PolicyPageOutcomeUnavailable), nil
	}
	sum := sha256.Sum256(scope)
	prefix := r.host.operatorEpoch + ":descriptions:" + hex.EncodeToString(sum[:]) + ":" + revision + ":"
	offset := 0
	if cursor != "" {
		word, ok := strings.CutPrefix(cursor, prefix)
		n, err := strconv.Atoi(word)
		if !ok || err != nil || n < 0 || n > len(actions) || strconv.Itoa(n) != word {
			return descriptionRefusal(wire.PolicyPageOutcomeGap), nil
		}
		offset = n
	}
	page := wire.DescriptionPage{Outcome: wire.PolicyPageOutcomePage, Revision: revision, Actions: []wire.DescribedAction{}}
	for offset < len(actions) && int64(len(page.Actions)) < limit {
		page.Actions = append(page.Actions, actions[offset])
		page.Complete = offset+1 == len(actions)
		page.Next = ""
		if !page.Complete {
			page.Next = prefix + strconv.Itoa(offset+1)
		}
		// Standard JSON escaping is at least as large as the wire escaping;
		// reserve space for snake-case keys, fixed-shape indentation and the reply envelope.
		data, err := json.Marshal(page)
		if err != nil {
			return descriptionRefusal(wire.PolicyPageOutcomeUnavailable), nil
		}
		if len(data)+2048+1024*len(page.Actions) > 256<<10 {
			page.Actions = page.Actions[:len(page.Actions)-1]
			if len(page.Actions) == 0 {
				return descriptionRefusal(wire.PolicyPageOutcomeUnavailable), nil
			}
			break
		}
		offset++
	}
	page.Complete, page.Next = offset == len(actions), ""
	if !page.Complete {
		page.Next = prefix + strconv.Itoa(offset)
	}
	if _, err = r.descriptionCaller(); err != nil {
		return descriptionRefusal(operatorPageError(err)), nil
	}
	return page, nil
}

func (r *operatorReceiver) RegisterDescribedAction(expected string, description wire.ActionDescription) (wire.DescriptionEdit, error) {
	by, err := r.authorize()
	if err != nil {
		return wire.DescriptionEdit{Outcome: operatorActionError(err)}, nil
	}
	result, err := r.host.policy.PublishAction(expected, description, by, func() error { _, err := r.authorize(); return err })
	if err != nil {
		return wire.DescriptionEdit{Outcome: operatorActionError(err)}, nil
	}
	return result, nil
}
