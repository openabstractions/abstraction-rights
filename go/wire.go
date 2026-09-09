package rights

import (
	"time"

	"github.com/openabstractions/abstraction-identity/listen"
)

const (
	RightAwake = "awake"

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

type Hold struct {
	App   string    `json:"app"`
	Name  string    `json:"name"`
	Right string    `json:"right"`
	Why   string    `json:"why"`
	Since time.Time `json:"since"`
	Seen  Seen      `json:"seen"`
}
