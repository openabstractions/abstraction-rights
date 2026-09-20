package client

// The generated contract types this package's API reaches, re-exported so an
// application names them through this package and never imports the generated
// one. scripts/idiom_check.py refuses a reachable type this file leaves out.

import (
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
)

type ActionEdit = wire.ActionEdit

type ActionEditOutcome = wire.ActionEditOutcome

const (
	ActionEditOutcomeApplied     = wire.ActionEditOutcomeApplied
	ActionEditOutcomeConflict    = wire.ActionEditOutcomeConflict
	ActionEditOutcomeUnknown     = wire.ActionEditOutcomeUnknown
	ActionEditOutcomeInvalid     = wire.ActionEditOutcomeInvalid
	ActionEditOutcomeExhausted   = wire.ActionEditOutcomeExhausted
	ActionEditOutcomeForbidden   = wire.ActionEditOutcomeForbidden
	ActionEditOutcomeUnavailable = wire.ActionEditOutcomeUnavailable
)

// ActionEditOutcomeValues returns every member of ActionEditOutcome in declaration order, in a new slice.
func ActionEditOutcomeValues() []ActionEditOutcome { return wire.ActionEditOutcomeValues() }

type DecisionOutcome = wire.DecisionOutcome

const (
	DecisionOutcomePermitted     = wire.DecisionOutcomePermitted
	DecisionOutcomeDenied        = wire.DecisionOutcomeDenied
	DecisionOutcomeNotGranted    = wire.DecisionOutcomeNotGranted
	DecisionOutcomeUnknownAction = wire.DecisionOutcomeUnknownAction
	DecisionOutcomeInvalid       = wire.DecisionOutcomeInvalid
	DecisionOutcomeForbidden     = wire.DecisionOutcomeForbidden
	DecisionOutcomeUnavailable   = wire.DecisionOutcomeUnavailable
)

// DecisionOutcomeValues returns every member of DecisionOutcome in declaration order, in a new slice.
func DecisionOutcomeValues() []DecisionOutcome { return wire.DecisionOutcomeValues() }

type PolicyEdit = wire.PolicyEdit

type PolicyEditOutcome = wire.PolicyEditOutcome

const (
	PolicyEditOutcomeApplied     = wire.PolicyEditOutcomeApplied
	PolicyEditOutcomeConflict    = wire.PolicyEditOutcomeConflict
	PolicyEditOutcomeInvalid     = wire.PolicyEditOutcomeInvalid
	PolicyEditOutcomeForbidden   = wire.PolicyEditOutcomeForbidden
	PolicyEditOutcomeUnavailable = wire.PolicyEditOutcomeUnavailable
)

// PolicyEditOutcomeValues returns every member of PolicyEditOutcome in declaration order, in a new slice.
func PolicyEditOutcomeValues() []PolicyEditOutcome { return wire.PolicyEditOutcomeValues() }

type PolicyPage = wire.PolicyPage

type PolicyPageOutcome = wire.PolicyPageOutcome

const (
	PolicyPageOutcomePage        = wire.PolicyPageOutcomePage
	PolicyPageOutcomeGap         = wire.PolicyPageOutcomeGap
	PolicyPageOutcomeInvalid     = wire.PolicyPageOutcomeInvalid
	PolicyPageOutcomeForbidden   = wire.PolicyPageOutcomeForbidden
	PolicyPageOutcomeUnavailable = wire.PolicyPageOutcomeUnavailable
)

// PolicyPageOutcomeValues returns every member of PolicyPageOutcome in declaration order, in a new slice.
func PolicyPageOutcomeValues() []PolicyPageOutcome { return wire.PolicyPageOutcomeValues() }

type RuleRead = wire.RuleRead

type RuleReadOutcome = wire.RuleReadOutcome

const (
	RuleReadOutcomeFound       = wire.RuleReadOutcomeFound
	RuleReadOutcomeExpired     = wire.RuleReadOutcomeExpired
	RuleReadOutcomeUnknown     = wire.RuleReadOutcomeUnknown
	RuleReadOutcomeInvalid     = wire.RuleReadOutcomeInvalid
	RuleReadOutcomeForbidden   = wire.RuleReadOutcomeForbidden
	RuleReadOutcomeUnavailable = wire.RuleReadOutcomeUnavailable
)

// RuleReadOutcomeValues returns every member of RuleReadOutcome in declaration order, in a new slice.
func RuleReadOutcomeValues() []RuleReadOutcome { return wire.RuleReadOutcomeValues() }

type ServiceError = wire.ServiceError

type ServiceErrorCode = wire.ServiceErrorCode

const (
	ServiceErrorCodeHandlerError   = wire.ServiceErrorCodeHandlerError
	ServiceErrorCodeInvalidResult  = wire.ServiceErrorCodeInvalidResult
	ServiceErrorCodeUnknownVersion = wire.ServiceErrorCodeUnknownVersion
	ServiceErrorCodeUnknownService = wire.ServiceErrorCodeUnknownService
	ServiceErrorCodeUnknownMethod  = wire.ServiceErrorCodeUnknownMethod
	ServiceErrorCodeWrongMode      = wire.ServiceErrorCodeWrongMode
)

// ServiceErrorCodeValues returns every member of ServiceErrorCode in declaration order, in a new slice.
func ServiceErrorCodeValues() []ServiceErrorCode { return wire.ServiceErrorCodeValues() }
