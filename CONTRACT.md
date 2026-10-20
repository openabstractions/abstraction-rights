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
unregistered action MUST imply permission. A configured account-wide default
(RIGHTS-R22) is a stated, named permit on one registered action, not an
implication (owner, VISION 2026-10-07). The generated `resource_actions`
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
decision-policy format `rights-decisions@7`, with canonical @2 to @6 still
readable; a version 1 file MUST be refused. Default switch state
(RIGHTS-R22) MUST appear only in @7. The seed may hold any bounded
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

A program compares as `abstraction-identity`'s `SameSubjectProgram` compares
two subject programs, in two steps (VISION.md L623: whether two paths name
one file is asked of the filesystem). A plain path first takes its canonical
spelling: a short (8.3) alias expands to the long name, also in an existing
folder above a file that does not exist yet. Byte-equal canonical names
are one program. Otherwise, when both programs exist on a local drive, they
are one program exactly when they are one file by file identity (volume
serial number and file ID): a junction and its target, and an 8.3 alias and
its long name, are one program; twins the volume keeps apart, such as names
differing by a KELVIN SIGN or a LONG S, and two files in a case-sensitive
folder (NTFS per-directory case sensitivity, which WSL sets on folders it
creates) whose names differ only in case, are two. When either does not
exist, as for a rule naming a program not yet installed, or is off a local
drive (identity ID-F1 `LocalPath`), such as one run from a share, the
canonical names decide, and a path off a local drive is never opened: on
Windows they are one name when they are equal under the file system's
ordinal case-insensitive comparison (the system uppercase table, as
`CompareStringOrdinal` applies it); on other platforms they MUST be equal
byte for byte. Unicode case folding MUST NOT decide either step. `Decide`, `DecideFor`, rule reads and operator edits MUST apply
this comparison, and a rule is stored in the spelling its edit gave.

A decision reads the caller's file identity at most once. It reads a stored
program's file identity once per policy revision and reuses that reading,
present or absent, for at most two seconds (`StoredKeyReuse`): a program
installed, removed or replaced after a reading is matched by its name at
once and by file identity within two seconds. A decision reuses the decoded
state for unchanged file bytes for the same two seconds. Rules whose programs compare equal on one action and
resource are one rule: a deny wins over a permit under either step, and of
two alike the later edit. An edit replaces them, a revoke removes them, and
the decision state merges them into one when the service loads it. An edit that writes a rule
for a path keeping a short alias that names no existing file or folder MUST
be refused as invalid: once a file appears there, its canonical spelling
differs and the rule could no longer be read for it.

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
owner. A revoke, Block or expiry of the rule ends the holder's live wake
leases, as RIGHTS-R23 ends every grant held past its call (abstraction-resource
RES-A1, RES-L7).

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

**[RIGHTS-R16] A class-scoped meta-rule carries the permits its holder
writes.** A meta-rule is a permit on `abstraction.asks/question.answer` for
the resource `apps`: its subject, the holder, may answer every app's routine
questions (asks ASK-R5; VISION 2026-10-03, "The 0.4.0 rights slice"). Its
permit MUST carry an expiry of at most 30 days (`MetaRuleLapse`); an edit
without one, or with a longer one, is `invalid`, and native `Set` refuses it.
A deny on it needs no expiry. The service's own program never holds one,
and neither does a program the host refuses through `MetaHolder`: the
runtime names its operator programs and script hosts there, since optional
cleanup may remove every permit the holder set, and an operator sets the
person's own rules; such an edit is `invalid`. The holder writes through `ChangeRulesUnderAnswer`,
one atomic edit that reads the holder's meta-rule and refuses unless it is
an unexpired permit; renews it to 30 days after the edit time; and writes
one or two exact permits in one edit, `set_by` the holder, expiring with the
meta-rule. A paired action conflicts as a unit before any permit is written. A holder
never writes a rule on `question.answer` and never a rule whose subject is
itself. A rule in force on the target that someone else set stays: a deny
reads `conflict`, and a permit stays the setter's while the write only
renews. Whenever the meta-rule's expiry moves, through a renewal or the
person writing it again, every permit its holder set that expired with it
moves too. Removing or denying the meta-rule ends future answers and leaves
the existing permits at their stamped expiry. `StopAnswerer` optionally
removes, in that same conditional edit, current permits whose `set_by` is the
selected answerer across enrollments; denies and another setter's current
rules remain. Without another answer, the enrollment and permits sharing
its expiry lapse within 30 days. Programs compare by the shared
subject-program rules. `RevokeAnswerPermits` removes only the current
permit effects that carry the retained answer's private question ID and
answerer identity among one or two targets; an older or replacement grant
stays. Zero matches conflict. The asks answer record remains historical.

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
selecting another revision or intent. Ordinary edits promise no automatic
retry, durable mutation receipt or exactly-once execution. The narrow
first-use Allow completion proof is specified in RIGHTS-O10. A successful revoke affects
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

**[RIGHTS-O9] Related first-use rules share one conditional edit.**
`SetRulesFor` accepts one or two exact rules with the same subject, resource
and permit and distinct catalogued actions. It checks the full group,
operator authority and expected revision under one rights edit, then writes
every member or none. An explicit operator edit may change an opposite
rule. A bounded delegated answer must preserve another setter's permit
and conflict on a live deny; the enrollment check and grouped preflight
happen before any renewal. The exact delegation's expiry is capped again
at the in-lock service time. Earlier `operator@1` services answer this
additive method `unknown_method`.

**[RIGHTS-O10] A completed operator Allow survives removal of its rules.**
`ApplyFirstUseAllow(expected_revision, question_id)` MUST derive its complete
one-or-two-rule permit from the actual retained operator Allow and the
runtime's admission. The receiving operator is authorized as in RIGHTS-O1.
Trusted composition MUST pin the Book occurrence and admission before
entering the rights edit; targets, actor, scope and options supplied by a
caller MUST NOT serve as evidence. A pending, missing, foreign, responder,
non-first-use or non-Allow record is `invalid`; absent composition is
`unavailable`. Historical records with no actor retain their legacy operator
interpretation. Context MUST bound Book and rights lock acquisition and be
rechecked with operator authority after lock waiting.

The complete permits and private occurrence-linked success proof MUST commit
in the same rights replacement. No rule removal, expiry sweep, replacement,
catalogue retirement or answerer cleanup may erase that proof. An
enrollment asked at first use (asks ASK-R10) is the one meta-rule an Apply
writes: a single `question.answer` permit on `apps`, carrying exactly
`MetaRuleLapse` as RIGHTS-R16 requires and no question identity, so no
answer-scoped removal reaches it; every other permit an Apply writes carries
no expiry. The host's `MetaHolder` refusal applies. A first Apply
with already matching live permits MAY write its receipt alone and change
the content revision. Ordinary setters keep their existing no-op semantics.
A completed occurrence or stale revision MUST return `conflict` with the
current revision and optional current rule, and MUST NOT restore lapsed
permits. Failed or conflicted first writes leave the answer retryable.

Private receipts are bounded to 4096 unique 32-hex occurrence IDs within
the existing 4 MiB state limit. Pruning MUST remove only IDs conclusively
absent from the fully pinned authoritative Book; retained proofs MUST NOT
be evicted by age or count. Canonical private `rights-decisions@2`, @3 and @4
remain readable; adding descriptions alone causes no eager migration.
Existing load-time subject canonicalization may write @5 and MUST preserve
completed receipts. An already-canonical legacy load, read or unchanged edit
MUST preserve file bytes; real edits write @5. Earlier
binaries refuse @5. Earlier operator@1 services return `unknown_method` for
this additive method; consumers MUST retain the answer and surface the
failure without falling back to an untracked permit write.

`StopAnswerer` withdraws the selected answerer's enrollment. Its
`also_revoke_grants` flag defaults false in the Panel; true removes all
current non-meta permits set by that answerer across enrollments in the
same edit, while preserving blocks and other setters' current rules.
`RevokeAnswerPermits` removes only live current permits whose private
question ID and setter match among one or two exact action targets. It
requires at least one match, preserves older and replacement effects, and
leaves the asks answer record intact. A migrated old permit without that
private ID cannot be selected by this operation. Both methods recheck
operator authority and expected revision inside the edit. The private
effect ID is stored in private rights files from version 3 onward, included in their
content revision, and omitted from the closed public `RuleRecord`. A
canonical version 2 file reads and migrates on its next write; older
runtime versions refuse the new profile.

**[RIGHTS-O11] An operator publishes an action's description conditionally.**
`RegisterDescribedAction` MUST use RIGHTS-O1 receiving authority, recheck it
inside the locked edit, and compare `expected_revision` before changing
state. It MAY register a new bounded action or describe an existing name,
including one already named by rules. An identical declaration MUST preserve
bytes, revision, publisher and publication time. A valid correction MUST
change only description metadata, publication provenance and the content
revision; every existing rule, expiry and completed-answer receipt MUST be
preserved. Retirement MUST remove the description with the action's rules.

The closed declaration MUST carry the stable action name, `feature_app`,
`app_label`, a plain description sentence and `declared_risk`. `feature_app`
identifies the operator-declared app whose feature is described; it MUST NOT
be used as an authorization target or caller identity. `published_by` MUST
identify the established receiving operator. Publication makes no claim that
an imported descriptor's author or vendor is independently verified. App
labels and descriptions MUST be trimmed, control-free UTF-8 strings of
1..128 and 1..512 bytes; declared risk MUST be 1..32 bytes. Routine,
sensitive, administrative and unknown are display words; a future word is
interpreted as unknown. Declared risk MUST NOT grant access, classify Asks
policy or change existing decision semantics. A feature whose actual
semantics change requires its app to use a new action name or version;
editing descriptive text supplies no proof of external behavior.

**[RIGHTS-R17] Published descriptions have a bounded public reader.**
`ListActionDescriptions` MUST require a freshly established same-account
Program caller, and recheck admission before returning. It MUST expose only
catalogue names and optional descriptions with publication provenance,
without rules. Each entry MUST carry the service's choices `allow`, `block`,
`remove_rule`; these name existing rule operations and grant no authority.
Description, publisher and timestamp MUST occur together. A page MUST have
1..64 requested entries, a reply within 256 KiB, and a cursor of at most 256
UTF-8 bytes. Continuations MUST bind the caller, service lifetime and policy
revision; mutation, restart or caller mismatch returns `gap`. Descriptions
MUST be sorted uniquely by registered action and fit the existing 64-action,
4 MiB state bounds. Earlier authorization@1 and operator@1 providers return
`unknown_method` for these additive methods. Consumers MAY retain their old
name-only presentation for that explicit compatibility result. Consumers
joining descriptions to editable rules MUST require the same revision;
failures or mismatches MUST NOT present a successful combined snapshot.

## Outcomes

### Typed selectors (`authorization@2`, `operator@2`)

**[RIGHTS-R18] A permission key retains its resource meaning.** Every typed
definition, decision, rule and effect MUST identify action and immutable
namespaced resource-profile version. The catalogue MUST retain explicit legacy
action-only routes and allow distinct full keys to coexist. It MUST NOT select
the latest profile or reinterpret an old exact resource, including literal `*`.
Resource types/codecs/equality MUST come from trusted capability composition;
publishing app metadata installs no validator, enforcer or authority.

One targets use bounded owning-IDL documents. All omits target and selects only
present/future members of the profile's fixed account/runtime collection, for
this action. The receiving capability MUST establish membership and the actual
bound resource. Public grant/Ask preparation MUST resolve requested targets
through the trusted capability owner. Caller-supplied captured FileKey MUST NOT
manufacture grant authority. Quiet policy evaluation MUST use pure canonical
validation/equality with receiver-retained evidence; it MUST NOT enter a resource
provider, perform backend effects, admit an Ask or reopen a historical image.
Read/removal of a saved canonical selector MUST address its exact retained bytes
without new target preparation. Retargeting/deletion MUST leave it manageable.

**[RIGHTS-R19] One snapshot decides the whole bounded batch.** CheckBatch MUST
validate/admit the complete query, read one immutable policy snapshot and sample
the service clock once. That snapshot read is the authority linearization point.
Results MUST carry that one revision, in input order. A stale expected revision
MUST return conflict and no collection/item outcomes; invalid, forbidden and
unavailable MUST return no outcomes or revision. Only permitted admits an effect.
A decision conveys no lease, post-boundary cancellation or distributed rollback.
Enforcers MUST recheck each emitted bounded page/effect, including after waiting.

Matching live One/All explicit blocks MUST defeat permits. Rights owns matching
and precedence. Collection admission considers All rules; a One block restricts
its concrete resource and MUST NOT cancel the All collection gate. Every outgoing
concrete resource still requires its matching result. Internal broad-consent
admission MAY conservatively refuse a proposal intersecting an explicit block;
it MUST expose no blocked names and MUST retain the original block.

**[RIGHTS-R20] Equivalent versions retain explicit restrictions.** Trusted
compiled capability equivalence MUST carry live explicit blocks bidirectionally
across overlapping effects, using the same snapshot. It MUST import no permits,
defaults or wildcard meaning. Expired blocks decide nothing. The bounded legacy
operation query MUST require original exact authority and validate the receiving
enforcer's actual operation/target against known equivalence. Coarse legacy
metadata/history decisions MUST conservatively deny the entire intersecting
view, preserving their success shape. Raw secret Read has no legacy equivalent;
internal runtime keys and native log sources have no invented saved-secret or
application-log membership. A bare public @1 decision MUST honor these fences.

**[RIGHTS-O12] Typed edits preserve revision, provenance and finite effects.**
Conditional selector/bundle edits MUST recheck operator authority after lock
waiting and compare the shared expected revision. A stale edit always conflicts,
including matching desired state. One bundle application MUST atomically expand
the complete immutable version into explicit rules with one setter/expiry and
retained original ref/digest/selector/member list. New actions/profile breadth
require new consent. Individual replacement MUST detach that row's old bundle
origin; origin removal MUST preserve later independent edits. Historical origin
MUST NOT be presented as a currently complete Full-control grant after partial
replacement/removal. Enumeration and policy administration require explicit
implemented members; named metadata supplies no unknown-name enumeration.

Typed first-use completion MUST derive only the pinned authoritative Book effect,
commit the whole effect and its success proof together, and refuse replay after
revocation/expiry. Undo MUST remove only still-current effects of that occurrence
and preserve later edits/blocks. Exact first-use@2 occurrences/receipts keep
their original meaning. New All/raw/elevated answering authority is never inferred
from old exact delegation. Proof may be pruned only after trusted occurrence
reclamation makes replay impossible.

**[RIGHTS-R21] Persisted meaning survives receiver unavailability.** The single
DecisionPolicy/CAS owner MUST read canonical old state@2..@6 and retain exact rules,
descriptions, typed state and proof in state@7. Known immutable target grammar validates saved
selectors/origins independently of current served/admissible availability. A
temporarily unserved receiver MUST NOT invalidate unrelated policy or prevent
read/removal of retained rules. New grants/checks for an unavailable receiver
MUST refuse. Unknown future grammar/version MUST fail closed with state recoverable.
Seed, durable state, deterministic compiled definitions/bundle content and
compatibility metadata contribute to one revision shared by v1/v2/Panel/Asks.
Function addresses do not participate. Changed validator meaning requires a new
immutable profile version. Descriptor corrections convey no authority change.

The combined state bound is 4096 rules and 4 MiB; completion proof remains bounded
by 4096 retained occurrences across namespaces. Batches contain at most 256
concrete resources plus one collection admission and fit the 1 MiB encoded frame.
Target documents are at most 16 KiB. Effects/bundles have at most 64 members.
Discovery has at most 256 definitions and 64 bundles. Existing account/program,
TTL/reason bounds apply. Pages have at most 64 entries and 256 KiB replies;
subject/host-epoch/revision/type-bound cursors are at most 256 bytes and gap after
change/restart. Capacity refusal performs no partial edit or silent proof eviction.
These contract additions describe the implemented owner boundary as slices land;
runtime advertisement still requires actual configured receiving enforcement.

**[RIGHTS-R22] An account-wide default permits where a program has no rule of
its own.** A host MAY configure, before serving, up to 32 named defaults, each a
permit on one registered action for one exact resource or for every resource of
that action, together with the one account whose programs receive them and the
programs excluded from every default. A legacy exact decision MUST evaluate, in
order: an unavailable state (`unavailable`), a live typed block (`denied`), the
subject program's own live exact rule on the target (its permit or deny), and
then the defaults. A default MUST permit only when its switch is on, the
subject's account is the configured account, and the subject is not excluded;
otherwise the outcome stays `not_granted`. An expired rule counts as none. A
default MUST write, remove or rewrite no rule, so a removed rule never returns
and a Block made for one program refuses that program alone. Each default is
one switch: on after a fresh install, stored only once an operator turns it,
as `{name, on, set_by, set_at}` in `rights-decisions@7`. The switch state and
the configured defaults MUST contribute to the policy revision. The installed
runtime configures five defaults (README), its own account, and the asks
script-host rule as the exclusion; a remote peer, decided under its mapped
namespace, receives none.

**[RIGHTS-R23] A grant held past its call lives only while its rule does.**
A decision admits one call. An owner that keeps something running after that
call returns, such as a lease, a live session or a durable job, MUST decide its
rule again, asking nobody, before each renewal, input or poll, and MUST end it
once the rule refuses: a revoke, a Block, a switched-off default and an expiry
alike. A decision it cannot obtain MUST NOT extend it, and MUST NOT shorten
or end it early either: it only stops extending it. The decision policy
MUST report each committed change, before the edit returns, to every function
added with `DecisionPolicy.OnChange`; each such owner adds one and decides
again on it, so a revoke ends what it admitted before its reply. An expiry
commits nothing, so each owner also decides again on its own clock. The owners
today are the resource lease book (abstraction-resource RES-L7, RES-A1),
the inference provider (abstraction-inference INF-A6) and the job acceptance
provider (abstraction-job JOB-A18). The Asks owner follows the same changes
to withdraw pending typed requests a change settled (abstraction-asks
ASK-A13). A remote peer's
work is decided under its mapped subject and ends the same way.

**[RIGHTS-O13] An operator reads and turns default switches conditionally.**
`ListDefaults` MUST return every configured default with its switch under one
revision, rechecking operator authorization before returning. `SetDefault`
MUST recheck authorization after lock waiting, compare the expected revision
(a stale revision conflicts), record the operator subject and service time,
and change no rule. An unconfigured name is invalid. A switch already in the
requested state at the matching revision is a no-op that keeps the revision.
An earlier operator@1 service returns `unknown_method`.

**[RIGHTS-O14] An operator reads why a subject is decided as it is.**
`ExplainFor(subject, action, resource)` MUST evaluate the subject on the exact
target through the same evaluation a decision makes, in its order (a live
typed Block, the subject's own live exact rule matched by program identity,
then the account-wide defaults, RIGHTS-R22), and MUST return that decision's
outcome and revision with the step that decided it: `typed_block`,
`own_rule`, `account_default` with the default's name, `default_excluded`
with the name of a default switched on for the target that the configured
exclusion keeps from this program, or `none`. It MUST recheck operator
authorization before returning, MUST NOT ask anybody, and MUST NOT write a
rule, record or decision cache entry. A refusal (`invalid`, `forbidden`,
`unavailable`) carries no revision, source or name. An earlier operator@1
service returns `unknown_method`.

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

**[RIGHTS-D1] Compiled permission definitions describe existing authority.**
`PermissionDefinition` is additive service-owned metadata for the stable action,
owning IDL operations, versioned resource profile, receiving enforcement,
disclosure, lifecycle and closed first-use behavior. Trusted composition binds
the record to a compiled owning validator. Unknown profiles/versions, duplicate
actions and incomplete bindings MUST be refused. Metadata supplies no callback,
grant or selector. A changed authority requires a new action identity/version.
The legacy exact-string profile preserves bounded exact bytes and literal `*`;
owning receiving services retain their existing domain validation. Defined but
unserved operations MUST be marked unserved and admit no first-use request.
Trusted composition supplies each capability-owned profile ID/version and one
validator shared by every definition referencing it. A missing referenced binding
MUST refuse construction. Metadata strings MUST be nonempty control-free UTF-8:
owner contract, profile and resource type are at most 128 bytes; operation entries
are at most 256 bytes; disclosure and lifecycle are at most 2048 bytes. Operation
and served-enforcer lists contain 1..64 distinct entries; enforcers are at most
128 bytes. Unserved definitions carry no enforcers and first_use=none.
Dynamic tier facts, attributed app-purpose descriptions and exact rules retain
their existing owners. This record adds no definition registration/list service.

## Not built

- The explicit lease design a generated `awake` profile call would need,
  end to end: the hold's record now lives in the resource lease book
  (RIGHTS-R14), and what has not moved off the holder's native connection
  is the request's own lifetime (RIGHTS-R12).
- Server authenticity: a reachable endpoint alone is not server trust,
  and this page builds no boundary for it (RIGHTS-A4).
- Operator UI and broader capability enforcement beyond this policy service.
