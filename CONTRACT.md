# abstraction.rights contract

Binds: `rights.thrift`

`abstraction.rights/authorization@1` is the generated policy decision
service: it decides whether one program may perform one named action on one
resource. `abstraction.rights/operator@1` is the companion service that
registers actions and edits the exact rules the decision service reads.
Resource services act as enforcement points and query the decision service
themselves before access; a registered action grants nothing by itself.
[README.md](README.md) is the walkthrough: obtaining the module, running it,
a worked `Decide` call, and the separately selected native
registration/token/awake-hold workflow.

## Reading this page

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY" and "OPTIONAL" in this page are to be
interpreted as described in RFC 2119 and RFC 8174, when, and only when, they
appear in all capitals, as shown here.

A rule id such as `RIGHTS-A1` is declared once, in bold brackets before its
title, at the head of the rule it names; tests and refusals cite it the same
way. A retired id is never reused; [HISTORY.md](HISTORY.md) keeps it with the
release it left. `HISTORY.md` also carries this contract's prior art and what
was measured or tested, linked from here and linking back.

| letter | meaning |
| --- | --- |
| A | admission — binding the caller before a decision |
| E | error and outcome — the outcome words a call can return |
| R | rule and policy — the decision service's own behaviour on stored rules |
| O | operator — `abstraction.rights/operator@1`, which edits that policy |

**Prose-to-wire.** The words below are the decided names
(`research/vocabulary/DECISION.md` D11, D88, S11); the wire still uses the
name on the right until the release named ships (`research/vocabulary/RENAME-PLAN.md`
§4), and the stored policy's dual reader accepts both names for that release.

| decided name | current wire name, until it ships |
| --- | --- |
| `abstraction.inference/chat.complete` | `abstraction.inference/complete` — first release after the docs |
| `abstraction.model/reference.resolve` | `abstraction.model/lookup` — second release |
| `abstraction.router/route.pick` | `abstraction.router/route` — second release |
| `abstraction.resource/lease.hold` | `abstraction.resource/hold` — second release |
| `abstraction.credentials/credential.apply` | `abstraction.credentials/apply` — second release |
| `abstraction.config/settings.edit` | `abstraction.config/editor@1` (today's resource value for config ReplaceUser) — third release |
| `abstraction.rights/policy.decide` | not yet a registered action; this contract's own operator/decision boundary has no gating action today |
| `abstraction.rights/policy.operate` | not yet a registered action; see above |
| `server:<name>` (resource) | `host:<name>` — first release |

## Rules

### Admission

**[RIGHTS-A1] Decide binds its own caller.** `Decide(action, resource)` MUST
derive the receiving subject from native Program proof; the caller supplies
no subject.

**[RIGHTS-A2] DecideFor binds the relaying caller and requires an explicit
enforcer.** `DecideFor(subject, action, resource)` MUST first check the
receiving account, then an explicit `AuthorizeEnforcer` callback for that
action and resource. A nil callback MUST refuse every relay call. The
authorized enforcer is trusted to assert its own actual bound subject;
serialization by itself conveys no proof.

**[RIGHTS-A3] A subject is an account and a program, never a verified
flag.** The program MUST be `msix:<package family name>` for a Windows
caller whose MSIX package identity is proven at `signed` and whose image
lies inside that package's installed folder, and MUST otherwise be the
normalized absolute executable path. Any process of the account can start an
arbitrary program with an installed package's identity. Identity alone
never names the package. Same-account access alone confers no
enforcement-point authority.

**[RIGHTS-A4] Both admission modes require the deciding service's own
account.** `Decide` and `DecideFor` MUST require the same account as the
deciding service's own. Remote subject assertion is outside this local
profile; server authenticity remains a separate unfinished boundary (see
[Not built](#not-built)).

**[RIGHTS-A5] SubjectFromPeer requires every shared Program requirement.**
`SubjectFromPeer` MUST require every shared Program requirement before
extracting account and program, which `abstraction-identity`'s
`SubjectProgram` names. Native path cleaning matches the receiving platform.
A program path identifies an unpackaged subject; moving the executable
changes identity. A package family survives package updates, whose image
paths change with every version; a process a packaged app starts has no
package identity of its own and keeps its path.

### Registered actions and policy

**[RIGHTS-R1] A registered action is a bounded, closed name.** The
registered actions are the decision service's configured seed plus every
action `RegisterAction` has added, bounded to 64 exact action strings of 128
bytes. A registered action name MUST match `<owner>/<name>`: owner is 1..64
bytes and name 1..63 bytes of lowercase ASCII letters, digits, `.`, `_` and
`-`, each beginning with a letter or digit. No prefix, wildcard, regex or
unregistered action MUST imply permission. The generated `resource_actions`
constant is the OA seed; [README.md](README.md) lists the actions the
installed runtime enforces.

**[RIGHTS-R2] A read is bounded and fails closed.** The Go provider MUST
bound each read of its state by `DecisionReadBudget`, 500 ms, and by the
call's context: a file whose read is denied MUST answer `unavailable` from
`Decide`, `DecideFor`, `ReadRule` and `ListPolicy` within that budget.
Unknown wire outcomes MUST refuse decoding rather than default to a known
one.

**[RIGHTS-R3] The Go client never treats an unclear reply as permission.**
The native `Client.Require` helper MUST preserve transport errors and MUST
return a typed `DecisionError` for every non-`permitted` outcome. No
unavailable or absent fallback MUST permit access. The default client adds a
finite five-second per-call budget and never retries; callers pass the same
context across their own operations.

**[RIGHTS-R4] A decision is a point-in-time observation.** Decisions MUST
carry no bearer token, lease or cached permission lifetime. Resource
services MUST recheck at their specified enforcement points. Revocation
affects the next fresh decision after a successful policy commit; it makes
no claim about effects already authorized or completed.

**[RIGHTS-R5] LoadDecisionPolicy requires explicit configuration and refuses
an unversioned file.** `LoadDecisionPolicy(path, seed)` MUST require explicit
operator configuration and a separate, private, service-owned file in
decision-policy format `rights-decisions@2`; a version 1 file MUST be
refused. The seed may hold any bounded
exact strings. The loader MUST refuse a file whose rules name an action
outside the seed and its registered actions, and MUST refuse a set of
registered actions above 64 entries.

**[RIGHTS-R6] Registering an already-registered action writes nothing.**
Native `RegisterAction` MUST add a `<owner>/<name>` action with the
service's own account and executable as registrant; an action already among
the registered actions MUST write nothing.

**[RIGHTS-R7] Native Set and Revoke are exact and atomic.** Native `Set` and
`Revoke` MUST operate under the existing CAS lock and atomic replacement. An
exact `Set` replaces one rule; an identical `Set`, and an absent `Revoke`,
MUST preserve the current revision. A successful `Revoke` MUST remove the
exact rule. A failed edit MUST return an error without claiming a
successful grant or revocation. An I/O error may leave the commit outcome
uncertain; operators reconcile or retry using the current policy decision
and revision. No process-local failure latch changes restart behaviour.

**[RIGHTS-R8] An installed decision file is required once it exists.** A
service whose installation created the file MUST set `StateRequired`. From
then on an absent file is an outage: decisions MUST read `unavailable`, and
native edits, registered-action entries and operator edits MUST refuse, so
a removed file never reads as an empty policy.

**[RIGHTS-R9] In-process decisions use the same binding and shape.** Native
`DecisionPolicy.Require(ctx, peer, action, resource)` MUST decide in the
deciding service's own process for a peer its receiving service bound, using
`SubjectFromPeer`, with the same result shape as the client's `Require`. A
runtime that serves its own resource services decides through it and
designates no enforcer. It MUST read the file on every call.

**[RIGHTS-R10] Field bounds and resource spelling.** Account MUST be 1..128
bytes; program MUST be
1..4096 bytes and absolute, or `msix:<package family name>`; action MUST be
1..128 bytes; resource MUST be 1..1024 bytes. All MUST be valid UTF-8
without control characters.

A resource is an opaque exact name. After wire decoding, `Set`, `Revoke`,
`Decide`, `DecideFor` and operator edits MUST compare it case-sensitively,
without trimming, Unicode normalization, or a global alias rule. For example,
`host:Ollama` and `host:ollama` name distinct rules; granting one does not
grant the other. The action's enforcing integration defines the canonical
spelling for identities it treats as equivalent, and MUST use that spelling
consistently in its decisions and policy edits. An Ollama integration that
lowercases model references before checking `ollama/model.pull` must have its
operator grant the lowercased resource, such as `library/model:latest`, even
when the displayed model name has capitals. Other resource namespaces can
preserve case where it distinguishes identities.

**[RIGHTS-R11] File bounds and validation.** The file MUST be bounded to 4
MiB and 4096 exact rules. Canonical provider JSON, version, the configured
registered actions and sorted unique rules MUST be validated on every read
and again in the locked edit. Duplicate rules, including conflicting exact
rules, MUST be refused. An oversize file, invalid Unicode, a nonregular
node, or unsupported state MUST be refused without a replacement write. The
parent directory belongs to the service; concurrent hostile namespace
replacement is outside this profile.

### The awake lease

**[RIGHTS-R12] The platform request and its connection lifetime stay
native.** The platform awake request and its connection lifetime stay
native: it is released when the holder closes, exits or is killed. A
generated-service call carries one request under a bounded call deadline (5
s at the rights service), and a hold carried by such a call ends at that
deadline while the holder is still connected (`go/awake_lease_test.go`). The
job runner's hold uses the in-process platform request and needs no rights
service.

**[RIGHTS-R13] Awake is an alias for a resource rule, not a registered
action of its own.** The awake hold's record is a lease of resource `awake`
under `abstraction.resource/leases@1` (abstraction-resource CONTRACT.md
RES-A1), and the rule it decides is `abstraction.resource/hold` on `awake`.
The word `awake` that `rights grant <app> awake` takes MUST be read as an
alias for that rule, by the same decision (`go/wire.go` `Alias`, `RightOf`).
Registrations already granted, and every reader of them, keep working.
`known_rights` still names `awake`, and `awake` MUST NOT be registered as an
action of its own: an action is `<owner>/<name>`, and the old word has no
owner.

**[RIGHTS-R14] A composed reader reads the resource lease book; a
standalone one reads its own list.** A service composed with the resource
lease book MUST write each hold there and MUST read `Holds` back from the
table's `awake` rows. One reader answers who holds the wake. A standalone
service keeps its own listing and reports no lease row. Neither one's
serialized metadata recreates a live lease. The platform request remains on
the holder's connection in both.

**[RIGHTS-R15] The versioned decision path and the legacy path never
mix.** Old binaries MUST NOT be pointed at the new decision-service path.
The current legacy `LoadPolicy` and mutation paths MUST refuse a versioned
decision file. This is cooperating-service authorization; OS sandboxing is a
separate mechanism.

### Operator

`abstraction.rights/operator@1` shares the configured decision endpoint.

**[RIGHTS-O1] Every operator method checks binding and authority before
touching policy.** The embedding service's `EnableOperator` MUST require a
trusted typed-peer callback before `Serve`. Each method MUST check the
receiving same-account Program proof and the callback before reading or
editing policy. `ErrOperatorForbidden` means denial; callback outage or
storage failure means `unavailable`. A nil authorization MUST refuse. The
callback must honour the bounded call context; it never parses formatted
`Seen` strings as evidence.

**[RIGHTS-O2] A policy subject an operator supplies is a target, never
proof.** Policy subjects an operator supplies are administrative targets.
They carry no proof and cannot authorize the operator or bypass receiving
resource checks.

**[RIGHTS-O3] ListPolicy pages are bounded.** `ListPolicy` MUST return the
current registered actions and 1..64 requested exact rules per page. Rules
are every retained rule, including an expired rule the next write removes.
The reply MUST be at most 256 KiB, with conservative record, registered-action,
indentation and envelope accounting. The registered actions MUST be at most
64 entries of 128 bytes each. The existing 4 MiB / 4096-rule persisted
limits remain.

**[RIGHTS-O4] A cursor is scoped and does not survive a change.** A cursor
(up to 256 UTF-8 bytes) MUST bind the caller's account and program, the
service epoch, and the exact policy revision. A change, a restart, or a
scope mismatch MUST return `gap`; callers explicitly restart from an empty
cursor. Stable content supports continuation replay. There is no
per-reader session, and no promise to replay historical changes.

**[RIGHTS-O5] SetRule and RevokeRule are compare-and-set against the
current content.** `SetRule` and `RevokeRule` MUST compare `expected_revision`
with the current content hash inside the existing atomic CAS edit, and MUST
recheck context and operator authority after lock waiting, before changing
policy. A mismatched revision MUST always return `conflict` and the current
revision and exact target rule, even when the desired content matches.
`Applied` carries the resulting revision and an optional current rule;
revocation carries none. A no-op edit preserves the revision and writes no
record. An empty policy has a stable content revision without creating the
file. The revision is a content identity: restoring identical content
restores that revision. Enumeration epochs change on restart; durable
content revisions do not.

**[RIGHTS-O6] A lost reply is reconciled, never retried blind.** A lost
mutation reply is uncertain. Explicitly retrying the same expected revision
cannot overwrite different current content, and may conflict after the
original change went through. Callers MUST reconcile current state before
selecting another revision or intent; no automatic retry, durable mutation
receipt or exactly-once execution is promised. A successful revoke affects
the next fresh authorization decision; effects already authorized, and
native connection-owned awake leases, keep their separate lifetime rules
(RIGHTS-R12).

**[RIGHTS-O7] Registering and retiring an action are compare-and-set edits
with closed outcomes.** `RegisterAction` and `RetireAction` MUST compare
`expected_revision` inside the same atomic edit and MUST recheck operator
authority after lock waiting. A stale revision MUST conflict, carrying the
current revision and any registered-action entry. Registering an
action already registered MUST apply without writing. A full set of
registered actions MUST return `exhausted`. `RetireAction` MUST remove the
registered-action entry and every rule naming the action; retiring a seeded
action is `invalid`, and retiring an action outside the registered actions
is `unknown`. A decision on a retired action reads `unknown_action`.
Adding an entry here is a registered-action entry, a different thing from
the registration the README defines (the device-authorization flow in
[`asks`](https://github.com/openabstractions/abstraction-asks)); a
registered-action entry names an action and authorizes nothing on its own.

**[RIGHTS-O8] Every rule records who set it, when, and for how long.**
Every rule MUST record `set_by`, `set_at` and `why`. `set_by` is the subject
the service established: the operator's receiving Program evidence, or the
service's own account and executable for native edits. `set_at` is service
time in UTC, RFC 3339 with milliseconds. `SetRule` records an empty reason
and no expiry. `SetRuleFor` records a reason of up to 256 bytes and an
expiry `ttl_ms` after the edit time, at most one year. A rule at or past its
expiry MUST decide `not_granted`. `ReadRule` MUST return it as `expired`
until the next policy write removes it, then as `unknown`. The service
clock is the only clock; callers never supply timestamps.

## Outcomes

**[RIGHTS-E1] The permit outcomes.** Only `permitted` permits resource
access. `denied` is an explicit exact deny. `not_granted` means no
unexpired exact rule exists. `unknown_action` means the action is outside
the current registered actions.

**[RIGHTS-E2] The refusal outcomes.** `invalid`, `forbidden` and
`unavailable` also refuse. An evaluated outcome carries the opaque policy
revision read with the decision. A storage, read or parse failure returns
`unavailable` without a revision.

| outcome | rule | meaning |
| --- | --- | --- |
| `permitted` | RIGHTS-E1 | the only outcome that permits access |
| `denied` | RIGHTS-E1 | an explicit exact deny |
| `not_granted` | RIGHTS-E1 | no unexpired exact rule |
| `unknown_action` | RIGHTS-E1 | the action is outside the registered actions |
| `invalid` | RIGHTS-E2 | malformed request; refuses |
| `forbidden` | RIGHTS-E2 | refused at the admission boundary; refuses |
| `unavailable` | RIGHTS-E2 | the decision point could not answer; refuses |
| `conflict` | RIGHTS-O5 | a compare-and-set mismatch on an operator edit |
| `exhausted` | RIGHTS-O7 | the registered actions are full |
| `gap` | RIGHTS-O4 | a `ListPolicy` cursor no longer matches |

## Bounds

| what | bound | rule |
| --- | --- | --- |
| registered actions | at most 64 entries of 128 bytes each | RIGHTS-R1, RIGHTS-O3 |
| registered action owner | 1..64 bytes | RIGHTS-R1 |
| registered action name | 1..63 bytes | RIGHTS-R1 |
| account | 1..128 bytes | RIGHTS-R10 |
| program | 1..4096 bytes | RIGHTS-R10 |
| action | 1..128 bytes | RIGHTS-R10 |
| resource | 1..1024 bytes | RIGHTS-R10 |
| decision file | 4 MiB, 4096 exact rules | RIGHTS-R11 |
| decision read budget | 500 ms | RIGHTS-R2 |
| default client per-call budget | 5 s | RIGHTS-R3 |
| generated-service call deadline for the awake hold | 5 s at the rights service | RIGHTS-R12 |
| `ListPolicy` page | 1..64 rules | RIGHTS-O3 |
| `ListPolicy` reply | at most 256 KiB | RIGHTS-O3 |
| `ListPolicy` cursor | at most 256 UTF-8 bytes | RIGHTS-O4 |
| `SetRuleFor` reason | at most 256 bytes | RIGHTS-O8 |
| `SetRuleFor` expiry (`ttl_ms`) | at most one year | RIGHTS-O8 |

## Divergences

- RIGHTS-E1 keeps the word **decision**, and the pair **permit**/**deny**,
  where the rest of this project now says outcome (`research/vocabulary/DECISION.md`
  D51). XACML names the same shape the same way, and this page's own
  services are `Decide`, `DecideFor` and `AuthorizationOperator`; renaming
  the word here would separate the prose from the wire it describes (D52).
- RIGHTS-R12 keeps the awake hold's lifetime on the holder's native
  platform connection instead of a generated `resource/leases@1` lease
  end to end. `abstraction-resource` CONTRACT.md RES-A1 records the same
  boundary from its own side: what moved to that table is the record, not
  the lifetime.
- The native registration/token/hold workflow README.md describes (RFC 8628
  device authorization, RFC 6750 bearer tokens) is a separately selected
  interface beside this generated decision service, not a second binding of
  it; no rule on this page governs it.

## Not built

- The explicit lease design a generated `awake` profile call would need,
  end to end: the hold's record now lives in the resource lease book
  (RIGHTS-R14), and what has not moved off the holder's native connection
  is the request's own lifetime (RIGHTS-R12).
- Server authenticity: a reachable endpoint alone is not server trust,
  and this page builds no boundary for it (RIGHTS-A4).
- Operator UI and broader capability enforcement beyond this policy service.
