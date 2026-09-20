# General authorization decisions

`abstraction.rights/authorization@1` is the generated policy decision service.
Resource services act as enforcement points and query it themselves before
access. The catalogue is the host's configured seed plus registered actions,
bounded to 64 exact action strings of 128 bytes. The generated
`resource_actions` constant is the OA seed; [README.md](README.md) lists the
actions the installed runtime enforces. A registered action is named
`<owner>/<name>`: owner is 1..64 bytes and name 1..63 bytes of lowercase ASCII
letters, digits, `.`, `_` and `-`, each beginning with a letter or digit. No
prefix, wildcard, regex or unknown action implies permission.

`Decide(action,resource)` derives the receiving subject from native Program proof.
`DecideFor(subject,action,resource)` first checks the receiving account and an
explicit host `AuthorizeEnforcer` callback for this action/resource. Nil refuses
every relay call. The authorized enforcer is trusted to assert its actual bound
subject; serialization itself conveys no proof. The subject has account and
program, with no verified flag. The program is `msix:<package family name>` for
a Windows caller whose MSIX package identity is proven at `signed` and whose image
lies inside that package's installed folder, and otherwise the normalized
absolute executable path. Any process of the account can start an arbitrary
program with an installed package's identity, so identity alone never names the
package. Same-account access
alone confers no enforcement-point authority. Both modes require the service's
account; remote subject assertion is outside this local profile.

`SubjectFromPeer` requires every shared Program requirement before extracting
account and program, which identity `SubjectProgram` names. Native path cleaning
matches the receiving platform. A program path identifies an unpackaged subject;
moving the executable changes identity. A package family survives package
updates, whose image paths change with every version; a process a packaged app
starts has no package identity of its own and keeps its path.
The shared platform's actual proof applies. Server authenticity remains a
separate unfinished boundary; a reachable endpoint alone is not server trust.

Only `permitted` permits resource access. `denied` is an explicit exact deny;
`not_granted` has no unexpired exact rule; `unknown_action` is outside the
current catalogue.
`invalid`, `forbidden`, and `unavailable` also refuse. Evaluated outcomes carry
the opaque policy revision read with the decision. Storage/read/parse failure
returns unavailable without revision. The Go provider bounds each read of its
state by `DecisionReadBudget`, 500 ms, and by the call's context: a file whose
read is denied answers `unavailable` from `Decide`, `DecideFor`, `ReadRule` and
`ListPolicy` within that budget. Unknown wire outcomes refuse decoding.
The Go native `Client.Require` helper preserves transport errors and returns a
typed DecisionError for every non-permitted outcome. No unavailable/absent
fallback permits access. Callers pass the same context across their operations;
the default client adds a finite five-second per-call budget and never retries.

Decisions are point-in-time observations. They carry no bearer token, lease or
cached permission lifetime. Resource services must recheck at their specified
enforcement points. Revocation affects the next fresh decision after a successful
policy commit. It makes no claim about effects already authorized or completed.

`LoadDecisionPolicy(path,seed)` requires explicit operator configuration and a
separate private service-owned file in profile `rights-decisions@2`; version 1
files refuse. The seed may hold any bounded exact strings. The loader refuses a
file whose rules name an action outside the seed and its registrations, and a
catalogue above 64 actions. Native `RegisterAction` adds a `<owner>/<name>`
action with the service's own account and executable as registrant; an action
already in the catalogue writes nothing. Native Set and Revoke operate under the existing
CAS lock/atomic replacement. An exact Set replaces one rule; identical Set and
absent Revoke preserve revision. Successful Revoke removes the exact rule.
Failed edits return errors without claiming a successful grant or revocation.
An I/O error may leave commit outcome uncertain; operators reconcile/retry using
the current policy decision/revision. No process-local failure latch changes
restart behavior. The additive operator profile below uses conditional edits.

A host whose installation created the file sets `StateRequired`. From then on
an absent file is an outage: decisions read `unavailable` and native edits,
registrations and operator edits refuse, so a removed file never reads as an
empty policy. Native `DecisionPolicy.Require(ctx, peer, action, resource)`
decides in the host's own process for a peer its receiving service bound, with
`SubjectFromPeer` and the same result shape as the client's `Require`. A
runtime that serves its own resource services decides through it and designates
no enforcer. It reads the file on every call.

Account is 1..128 bytes; program is 1..4096 bytes and absolute, or
`msix:<package family name>`; action is 1..128
bytes; resource is 1..1024 bytes. All are valid UTF-8 without control characters.
The file is bounded to 4 MiB and 4096 exact rules. Canonical provider JSON,
version, configured catalog and sorted unique rules are validated on every read
and again in the locked edit. Duplicate rules, including conflicting exact
rules, refuse. Oversize, invalid Unicode, nonregular nodes or unsupported state
refuse without a replacement write. The parent directory belongs to the service;
concurrent hostile namespace replacement is outside this profile.

Existing registration secrets, bearer tokens and connection-owned awake leases
retain their native service and persistence unchanged. The awake lease stays
native because its lifetime is the holder's connection: the platform request is
released when the holder closes, exits or is killed. A generated profile call
carries one request under a bounded call deadline (5 s at the rights host), and
a hold carried by such a call ends at that deadline while the holder is still
connected (`go/awake_lease_test.go`). A generated awake profile needs an
explicit lease design: acquisition reply, renewal interval, expiry after holder
death and revocation effect. The job runner's hold uses the in-process platform
request and needs no rights service. Their serialized metadata
does not recreate a live lease. Old binaries must never be pointed at the new
decision-profile path. Current legacy LoadPolicy and mutation paths refuse a
versioned decision file. Operator UI and broader capability enforcement remain
separate integration obligations. This is
cooperating-service authorization; OS sandboxing is a separate mechanism.

## Explicitly authorized policy operators

`abstraction.rights/operator@1` shares the configured decision endpoint. Host
EnableOperator requires a trusted typed-peer callback before Serve. Each method
checks receiving same-account Program proof and the callback before reading or
editing policy. ErrOperatorForbidden means denial; callback outage or storage
failure means unavailable. Nil authorization refuses. The callback must honor
the bounded call context; it never parses formatted Seen strings as evidence.
Policy subjects supplied by an operator are administrative targets. They carry
no proof and cannot authorize the operator or bypass receiving resource checks.

ListPolicy returns the current catalogue and 1..64 requested exact rules per
page. Rules are every retained rule, including expired rules the next write
removes. The reply is at most 256 KiB with conservative record, catalogue,
indentation and envelope accounting. The catalogue has at most 64 actions of
128 bytes each. The existing 4 MiB/4096-rule persisted limits remain. A cursor
(up to 256 UTF-8 bytes) binds caller account/program, host epoch and exact policy
revision. Changes, restart or scope mismatch return gap; callers explicitly
restart from an empty cursor. Stable content supports continuation replay.
There is no per-reader session and no promise to replay historical changes.

SetRule and RevokeRule compare expected_revision with the current content hash
inside the existing atomic CAS edit. They recheck context and operator authority
after lock waiting, before changing policy. A mismatched revision always returns
conflict and its current revision/exact target rule, even when desired content
matches. Applied carries the resulting revision and optional current rule;
revocation has none. No-op edits preserve revision and write no record. Empty
policy has a stable content revision without creating the file. The revision
is a content identity: restoring identical content restores that revision.
Enumeration epochs change on restart; durable content revisions do not.

A lost mutation reply is uncertain. Explicitly retrying the same expected
revision cannot overwrite different current content, and may conflict after the
original change. Reconcile current state before selecting another revision or
intent. No automatic retry, durable mutation receipt or exactly-once execution
is promised. A successful revoke affects the next fresh authorization decision;
effects already authorized and native connection-owned awake leases keep their
separate lifetime rules.

## Catalogue registration, rule expiry and provenance

RegisterAction and RetireAction compare expected_revision inside the same
atomic edit and recheck operator authority after lock waiting. A stale revision
conflicts and carries the current revision and any registration entry.
Registration grants nothing: decisions on a new action read `not_granted` until
a rule exists. Registering a catalogued action applies without writing. A full
catalogue returns `exhausted`. RetireAction removes the registration and every
rule naming the action; retiring a seeded action is `invalid`, and retiring an
action outside the catalogue is `unknown`. Decisions on a retired action read
`unknown_action`.

Every rule records `set_by`, `set_at` and `why`. `set_by` is the subject the
service established: the operator's receiving Program evidence, or the service's
own account and executable for native edits. `set_at` is service time in UTC,
RFC 3339 with milliseconds. SetRule records an empty reason and no expiry.
SetRuleFor records a reason of up to 256 bytes and an expiry `ttl_ms` after the
edit time, at most one year. A rule at or past its expiry decides `not_granted`.
ReadRule returns it as `expired` until the next policy write removes it, then as
`unknown`. The service clock is the only clock; callers never supply
timestamps.
