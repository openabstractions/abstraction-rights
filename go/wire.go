package rights

import (
	"time"

	"github.com/openabstractions/abstraction-identity/listen"
)

// RightAwake is the word this service has always taken for the wake hold, and
// the word `rights grant <app> awake` still writes. The hold itself is a lease
// of resource awake under abstraction.resource/leases@1
// (abstraction-resource CONTRACT.md RES-A1), and the rule is
// AwakeAction on AwakeResource. Both words name one decision, so the rules a
// person already wrote and the Panel that reads them keep working.
//
// AwakeAction is not spelled here as an action anybody could have written a
// rights rule on: a catalogue action is <owner>/<name>, and `awake` has no
// owner. The old word lives on this service's own registrations, and Alias is
// where it becomes the rule.
const (
	RightAwake = "awake"

	AwakeAction   = "abstraction.resource/hold"
	AwakeResource = "awake"

	OpRegister = "register"
	OpAsk      = "ask"
	OpHold     = "hold"
	OpCheck    = "check"

	OpApps   = "apps"
	OpGrant  = "grant"
	OpRevoke = "revoke"
	OpForget = "forget"
	OpHolds  = "holds"
)

var Known = []string{RightAwake}

// Alias is the exact rule a held right decides as. A right this service takes
// and the rule a decision point reads are the same decision under two words.
func Alias(right string) (action, resource string, ok bool) {
	if right == RightAwake {
		return AwakeAction, AwakeResource, true
	}
	return "", "", false
}

// RightOf is Alias the other way: the word this service takes for one exact
// rule, for a reader that has the rule and wants the registration.
func RightOf(action, resource string) (string, bool) {
	if action == AwakeAction && resource == AwakeResource {
		return RightAwake, true
	}
	return "", false
}

type Request struct {
	Op     string   `json:"op"`
	Name   string   `json:"name,omitempty"`
	Rights []string `json:"rights,omitempty"`
	Secret string   `json:"secret,omitempty"`
	Token  string   `json:"token,omitempty"`
	Right  string   `json:"right,omitempty"`
	Why    string   `json:"why,omitempty"`
	App    string   `json:"app,omitempty"`
	Admin  string   `json:"admin,omitempty"`
}

type Response struct {
	Code    string    `json:"code,omitempty"`
	Error   string    `json:"error,omitempty"`
	Secret  string    `json:"secret,omitempty"`
	Token   string    `json:"token,omitempty"`
	Expires time.Time `json:"expires,omitzero"`
	App     *App      `json:"app,omitempty"`
	Right   string    `json:"right,omitempty"`
	Apps    []App     `json:"apps,omitempty"`
	Holds   []Hold    `json:"holds,omitempty"`
}

type App struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Rights     []string  `json:"rights"`
	Registered time.Time `json:"registered"`
	Seen       Seen      `json:"seen"`
}

type Seen = listen.Seen

// Lease names the row of the resource table's awake resource this hold is
// (abstraction-resource CONTRACT.md RES-A1). It is empty for a service
// composed without a lease book, which keeps its own listing.
type Hold struct {
	App   string    `json:"app"`
	Name  string    `json:"name"`
	Right string    `json:"right"`
	Why   string    `json:"why"`
	Since time.Time `json:"since"`
	Seen  Seen      `json:"seen"`
	Lease string    `json:"lease,omitempty"`
}
