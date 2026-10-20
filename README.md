# abstraction-rights

*For applications that check a decision and operators who grant rules.
Services that enforce rights read the `Require` paragraph below.*

Rights are permissions: a person gives one program permission to perform one
named action on one resource, inspects that decision, and revokes it without
changing the application. Every protected service checks rights at the resource
boundary. A rule identifies the account, the OS-bound program, the action and
the resource; a registered action grants nothing by itself. An application
checks its own decision as shown in
[Decide from an application](#decide-from-an-application).

**What's new here:** A permission names one proven program: each rule is an
exact program, action and resource, decided at each service boundary, and a
refused first use becomes one question to the person.

Services call the generated `abstraction.rights/authorization@1` decision
service. `Require(ctx, peer, action, resource)` permits only an explicit
`permitted` result. [General decision contract](CONTRACT.md) defines trusted
enforcement points, exact rules, revision and revocation semantics. The native
registration/token/awake workflows below are separately selected interfaces.

Rights covers every protected OA action, including configuration edits, log
history, model lookup, routes, durable job submission and cancellation,
credential use, inference, application discovery and activation, storage, asks
and keep-awake holds.

The [permission journey](https://github.com/openabstractions/abstractions/blob/main/examples/rights-playground/README.md)
connects current exact rules to native consent and a credential-bearing effect.
It also explains the implemented selector-aware interfaces: one/all scope, a finite
versioned full-control bundle, explicit Block precedence and effective access
after rule removal. The connected runtime advertises current receiving support;
the journey records platform and human acceptance separately.

An assistant becomes an answerer only after the person enrolls its program in
the Panel. The class-scoped `abstraction.asks/question.answer` permit on `apps`
lets it answer routine first-use questions about other apps. The answerer's
permit for an app shares the enrollment's stamped expiry; each applied answer renews its 30-day
idle expiry. Stopping the answerer ends its future answering. The person may
also revoke its current permits in the same policy edit. Any permits left in
place keep their stamped expiry. Sensitive and administrative questions stay with the person,
and the runtime refuses script hosts as answerers (RIGHTS-R16, asks ASK-R5 to
R7). The Panel shows the answerer and each answer under Answered for you.
Undo removes only still-current permissions from that exact answer, preserving
newer and older grants. A paired first-use allow writes both permissions in
one rights edit, so a conflict cannot leave half a pair.

Operators inspect and change exact rules with the generated operator client or
CLI:

```console
openabstractions rights list --json
openabstractions rights decide --action <action> --resource <resource>
openabstractions rights grant --program /absolute/path/to/app \
  --action <action> --resource <resource> --why "operator choice"
```

`grant --for downloads` and `grant --for inference` write a bundle of exact
rules for one program, one conditional edit at a time, and report every rule
that landed. `--for` and the bundles it names belong to the `openabstractions`
runtime program, not to this module; the rules they write are exact rules
this module decides on like any other.

- `downloads` grants `abstraction.job/acceptance.submit` on
  `job:download`, `abstraction.model/lookup` on each
  `--registry`, and `abstraction.credentials/apply` on each `--credential`.
- `inference` grants `abstraction.router/inventory.read` on
  `abstraction.router/inventory`, `abstraction.router/route` on
  `abstraction.router/routes`, `abstraction.job/acceptance.submit` on
  `job:inference` (image batches and video are submitted as jobs; no other
  kind, a download among them), `abstraction.inference/complete` on
  `host:<name>` for each
  `--host`, `abstraction.storage/content.write` and `content.read` on
  `output:<profile>` for each `--output` (`image`, `video`, `speech`; the read reaches
  only the program's own results), and `abstraction.credentials/apply` on
  each `--credential`. No input profile is in a bundle: the request that
  consumes an input asks for it.

Resource services remain the enforcement points and return their own typed
`forbidden` or `unavailable` outcomes.

An operator first-use Allow is recorded through asks, then applied through
rights `ApplyFirstUseAllow(expected_revision, question_id)`. Trusted runtime
composition derives every exact permit from that retained answer and commits
its completion proof with the complete policy edit. Revoking or expiring the
permits keeps the proof; a fresh denied request can ask again immediately.
A write that never completed remains available for the Panel's Retry rule.
Completed IDs conflict on Retry and cannot restore revoked grants. Earlier
runtimes return `unknown_method`; update the runtime before applying that
Allow. Custom Go `grants.RuleOperator` implementations retain their existing
interface; an Allow requires the additive completion method and reports
`unavailable` when absent, keeping the answer for Retry/Dismiss. Ordinary
operator edits keep their existing meanings.

The private decision file writes `rights-decisions@7` and reads canonical @2
to @6. Already-canonical legacy loads, reads and unchanged edits preserve
the bytes; existing load-time subject canonicalization may write @7 while
preserving completed proofs. Real edits write @7. Earlier binaries refuse @7.
Its at-most-4096 completion IDs are pruned only when absent from the pinned
Book; retained proofs survive rule removal, expiry and catalogue retirement.

The table says which host enforces each action. **Installed** is
`openabstractions serve runtime`: it decides in its own process against
`rights/decisions.json` in its state directory, through
`DecisionPolicy.Require`, and designates no enforcer. **Library** is the facade
runtime's `*FromRights` helper, which a host composing that service configures
with any `Decider`: the IPC client or an in-process policy. The runtime
registers each action into its policy at composition; the job, asks,
credentials and inference definitions declare their own `resource_actions`.

| service call | action | resource | host |
| --- | --- | --- | --- |
| config ReplaceUser | `abstraction.config/user.replace` | `abstraction.config/editor@1` | installed |
| logging history read and observe | `abstraction.logging/history.read` | `abstraction.logging/history` | installed |
| model lookup | `abstraction.model/lookup` | requested registry name | installed |
| router Models, Hosts | `abstraction.router/inventory.read` | `abstraction.router/inventory` | installed |
| router Pick | `abstraction.router/route` | `abstraction.router/routes` | installed |
| job Submit | `abstraction.job/acceptance.submit` | `abstraction.job/acceptance@1` for every kind and `job:<kind>` of the submission; a deny on either wins (JOB-A13) | installed |
| job operator ListAccountWork | `abstraction.job/inventory.read` | `abstraction.job/acceptance@1` | installed |
| job operator CancelOperation | `abstraction.job/acceptance.cancel` | `abstraction.job/acceptance@1` | installed |
| credentials manage, read, apply | `abstraction.credentials/holder.manage`, `holder.read`, `apply` | `account`, `credential:<name>` | installed |
| inference complete, host management, key issue, audit read | `abstraction.inference/complete`, `host.manage`, `key.issue`, `audit.read` | `host:<name>`, `account` | installed |
| asks application Ask | `abstraction.asks/question.ask` | `account` | installed |
| applications Register, Remove | `abstraction.facade/application.manage` | `account` | installed |
| applications Register of the caller's own descriptor | `abstraction.facade/application.register_self` | `account` | installed |
| asks notification posting (registered; the posting service is planned) | `abstraction.asks/notification.post` | `account` | installed |
| applications Announce, Withdraw | `abstraction.facade/application.announce` | `app:<descriptor>` | installed |
| applications Observe | `abstraction.facade/application.read` | `app:<descriptor>` | installed |
| applications Activate | `abstraction.facade/application.activate` | `app:<descriptor>` | installed |
| provider registry changes | `abstraction.facade/provider.manage` | `account` | installed |
| storage inventory source registration | `abstraction.storage/inventory.provide` | `store:<name>` | installed |
| storage Open | `abstraction.storage/content.read` | content digest | library |
| storage Begin, Append, Commit | `abstraction.storage/content.write` | content digest | library |
| generated output publication and read-back (inference INF-S7); one first-use answer writes both for `output:image`, `output:speech` or `output:video`, and the read reaches only the program's own results | `abstraction.storage/content.write` and `content.read`, both | `output:speech`, `output:live`, `output:image`, `output:video` | library |
| request input upload and read-back for the writer's own request (storage STO-W12, inference INF-V4) | `abstraction.storage/content.write` and `content.read`, both | `input:image`, `input:audio` | library |
| storage change Observe, List | `abstraction.storage/content.observe` | `abstraction.storage/changes` | library |
| storage Remove | `abstraction.storage/content.remove` | `store:<name>` | library |

The actions and resources above are today's wire strings. `model/lookup`,
`router/route`, `credentials/apply`, `inference/complete` and the resource
`host:<name>` are renamed by `research/vocabulary/DECISION.md` (S11, D11,
D88); [CONTRACT.md](CONTRACT.md#reading-this-page) carries the full
prose-to-wire table and the release each rename ships in. A rule written
against the string in this table keeps deciding until that release's dual
reader is in place.

Config reads, log writes, a program's own work (cancellation included), its own
questions and its own `Decide` need no rule. An evaluated refusal reaches the
caller as that service's `forbidden` outcome. A decision the service cannot
obtain, including an unreadable or removed policy file, reaches it as
`unavailable` within half a second, with no state changed. While the file
cannot be read, the runtime's resolver reports `abstraction.rights/authorization@1`
and `abstraction.rights/operator@1` not ready, checked once a second.

**Installation rules.** When the runtime first composes a capability it writes,
for each operator program (the runtime, `openabstractions`, `openabstractionsw`
and `Abstraction Panel` beside it), a permit rule with why `installation` for
each composed capability (`serve/runtime_rights.go` `installationRules`), and
records each in `rights/defaults-applied`:

- config `user.replace`; logging `history.read`;
- job `acceptance.submit`, `acceptance.cancel` and `inventory.read` on
  `abstraction.job/acceptance@1`;
- model `lookup` on each composed registry;
- router `inventory.read` and `route`; resource `table.read`;
- resource `hold` on `card:0` and on `awake`, and `yield` on each attached
  engine host the runtime can ask to unload;
- credentials `holder.manage` and `holder.read`;
- inference `host.manage`, `key.issue`, `audit.read`, `selection.manage` and
  `selection.manage_for`;
- facade `application.manage` and `provider.manage`.

A rule the person revoked is never written again. Installation names no
application: reading and starting a registered entry follow its registration
(facade `APPLICATIONS.md`). Applications hold no rule by installation; the
defaults for all apps below apply to them. A person grants one with
`openabstractions rights grant`, `rights grant --for downloads|inference`, the
Panel's Rights and Explore sections, or by answering the question the runtime
asks when a job submit, model lookup or inference complete first decides
`not_granted`.

**Defaults for all apps.** The installed runtime configures five account-wide
defaults (RIGHTS-R22, VISION 2026-10-07). Each permits every program of the
runtime's own account that has no rule of its own on the target, and each is
one switch, on after a fresh install:

| default | action | resource |
| --- | --- | --- |
| `register` | `abstraction.facade/application.register_self` | `account` |
| `ask` | `abstraction.asks/question.ask` | `account` |
| `announce` | `abstraction.facade/application.announce` | every `app:<name>` |
| `notify` | `abstraction.asks/notification.post` | `account` |
| `download` | `abstraction.job/acceptance.submit` | `job:download` |

A rule made for one program, a Block included, wins over the default. A
script host never receives a default, and a remote peer, decided under its
mapped namespace, receives none. The Panel's Permissions page ("Defaults for
all apps") and `openabstractions rights defaults [--on NAME | --off NAME]`
turn each switch off and on through `operator@1` `ListDefaults` and
`SetDefault` (RIGHTS-O13). A default writes no rule. `operator@1`
`ExplainFor` (RIGHTS-O14) answers, for one program and target, the decision
and the step that made it (its own rule, a typed Block, a default by name, a
default the program is excluded from, or none); an app's Panel page lists a
default as "Allowed for all apps" only where it says so.

A permission a person grants to an application is recorded as a rule. The
resource service rechecks it at its specified enforcement points. A
successful revoke affects the next fresh decision; effects already
authorized and native connection-owned awake holds retain their own
lifetimes ([CONTRACT.md](CONTRACT.md), RIGHTS-R4/R12/O6).

## How an application gets a rule

An authorized operator can publish a custom action's description with
`openabstractions rights register-action --description-file action.json`.
The closed JSON file has `action`, `feature_app` (required `account` and
absolute `program`), `app_label`, `description` and `declared_risk` strings.
For example, an OpenCode deployment declares `opencode/log-source.share`
with its actual account and installed executable, the label `OpenCode`, a
sentence explaining that event contents are shared with its assistant model,
and risk `sensitive`. The registering command's established operator is
recorded as publisher. The feature app names whose feature is described;
the exact subject and resource of a permission remain separate.

Publication uses a policy revision and grants no rule. Metadata corrections
preserve existing rules and completed answers. Same-account Program clients
read the catalogue through `ListActionDescriptions`; earlier providers may
return `unknown_method`. Descriptive risk is display metadata, with unknown
values displayed as unknown. The application still enforces its action with
`Decide` at every disclosure boundary (RIGHTS-O11/R17/R4).

A person grants a rule, through `openabstractions rights grant` on the command
line or the Panel's Rights and Explore sections. An application never grants
its own rule and never holds one by installation.

For job submit, model lookup, inference complete and storage lend, the
runtime asks the person when an application's call first decides
`not_granted`: the question names the program, the action and the resource,
and an authorized operator applies Allow as an exact permit or Never as an
exact deny; Refuse writes no rule. Asks records the answer, and the rights
operator applies the effect (ASK-R2, RIGHTS-O10). A
request that consumes an input profile, and a job refused for want of its
output profile (`output:image`, `output:video`), admit one paired question
whose allow writes both content rules on that profile. A job missing several
grants is refused once, naming each, and admits all their questions in the
same pass.

## Decide from an application

```go
package main

import (
	"context"
	"log"

	facade "github.com/openabstractions/abstraction-facade/go"
)

func main() {
	ctx := context.Background()
	rights, err := facade.Discover().ResolveRights(ctx, facade.Requirements{})
	if err != nil {
		log.Fatal(err)
	}
	decision, err := rights.DecideContext(ctx, "abstraction.credentials/apply", "credential:openrouter")
	if err != nil {
		log.Fatal(err)
	}
	log.Println(decision.Outcome) // "permitted", "denied", "not_granted", "unknown_action"
}
```

An application cannot register its own action today; `RegisterAction` is an
operator call, made by the service that owns the action. What an application
can do is read a decision: call `Decide` or `DecideFor` for an action and a
resource (the rights target string) the runtime already registered, and get
back the decision the enforcing service then honors.

`DecideContext` derives the subject from the calling program's own native
identity. Only `permitted` authorizes the caller to proceed; every other
outcome refuses. A resource service deciding on another program's behalf
calls `Require(ctx, peer, action, resource)` instead, over the peer it bound
at its own receiving boundary.

## The problem

Every application that wants to hold the machine awake asks the operating
system itself, and nothing on the machine can say who is holding it or take the
hold away. This is a local service that issues tokens for rights a person has
granted, and a tool that edits the grants. The first right is `awake`: may this
application hold the machine awake. The service holds the OS request on the
application's behalf, so revoking the right releases the machine the same
second.

The resource layer holds the `awake` state today, as a lease of its `awake`
resource. This layer keeps `awake` as a one-line alias for that lease's rule;
grants a person already made, and every reader of them, keep working.

## Words

| word | meaning |
|---|---|
| **resource right** | one name from a closed vocabulary the registration/token/hold workflow below grants; the first is `awake`. Everything not on the list is absent, and absent means no |
| **registration** | the device authorization grant (RFC 8628): an application connects, says its name and the rights it wants, and waits for a person |
| **grant** | a person's act; its subject is the application, designated by its secret |
| **token** | a bearer credential (RFC 6750) scoped to one resource right and one hour |
| **hold** | a resource right in use, kept by the service on the application's behalf |
| **check** | token introspection (RFC 7662) for a resource holder in another process |

Elsewhere on this page, "right" means an ordinary rule: permission for one
program to perform one action on one resource, the kind `Decide` and
`DecideFor` check.

No rule on this page carries a tag; the contract below is held by the tests
named in it.

## Obtain

- **Go.** `go get github.com/openabstractions/abstraction-rights/go`. No tag
  yet; `go get` resolves a pseudo-version of `main`. Standard library plus
  [abstraction-identity](https://github.com/openabstractions/abstraction-identity)
  (which brings `golang.org/x/sys`).
- **Other languages.** See generated protocol and shared transport/client packages
  in this repository and the facade. Native provider support is separate.

## Run

Install the runtime first: https://openabstractions.org/adopt.html. It serves
rights and questions through local IPC. Use the installed command line to
inspect and edit the operator policy:

    openabstractions rights list
    openabstractions rights grant --program C:\tools\app.exe --action ACTION --resource RESOURCE
    openabstractions questions pending

For an explicit resource permission, use its action and resource pair as shown
by the application or panel. The command resolves the runtime's operator
profile over IPC; it does not read a service admin secret.

### Legacy standalone rights and keepawake example

The repository retains `rights` and `keepawake` for standalone compatibility;
the asks repository has `asksd` and `asks`. The rights service itself runs as
`openabstractions serve rights`, with the flags the retired `rightsd` took:
the asks layer depends on rights, so the program that joins the two is the
runtime's host command. This flow uses the legacy rights and asks services,
including their secret-based admin commands; it is separate from the installed
runtime path above. Do not start those services beside the runtime on their
default endpoints.

    go build -o bin/ ./go/cmd/...
    bin/asksd
    openabstractions serve rights
    bin/keepawake encoding a long video
    bin/asks pending
    bin/asks answer 5a20a0 allow
    bin/rights holds
    bin/rights revoke keepawake awake

The legacy standalone policy lives in `policy.json` under
`os.UserConfigDir()/openabstractions/rights`, or `-state <dir>` on its
programs. A registration answered *never* is refused without asking for as
long as that answer stands.

## Contract

Your application can distinguish a missing grant from an invalid token without
parsing an error message. The message is for the person; the code is for the program.

Service refusals carry an optional stable `code` alongside the existing diagnostic
`error` text. Either nonempty field means refusal. Old text-only replies remain
valid; unknown codes remain refusals and must not be treated as success. Servers
continue sending diagnostic text for older clients. Go clients return
`*RemoteError`, retaining the code and message; `Response.Err()` applies the same
rule to a decoded reply. Known native sentinels remain accessible through
`errors.Is`. The [code constants](go/errors.go) define the vocabulary; an
unclassified service failure uses `internal`. Diagnostic wording is not an API.

**Legacy standalone token authority is designation, not identity.** This is
OAuth's shape, and the three pieces map onto it directly. The installed runtime
uses its rights operator profile over IPC.

- **Registration is the device authorization grant (RFC 8628).** The
  application connects, says its name and the rights it wants, and waits. The
  request is a question in [`asks`](https://github.com/openabstractions/abstraction-asks) — with what the platform
  could prove about who connected, via `identity.Bind` — and a person answers
  it there. That answer is not kept: every registration is shown, because the
  path is the point. The secret goes back
  over the same connection the identity was bound on. It never touches a
  command line, an environment, or a file the service chose.
- **Every operation binds its caller before it reads the request.** All nine
  go through `listen.Receive`, which hands over the frame only together with
  the program the kernel says sent it, checked against `listen.Program`. A
  caller the kernel cannot identify is refused with the reason
  (`rights: refused, identity: ...`) and its request is never parsed; the
  service refuses to start on a machine that cannot bind at all
  (`identity.CanEver`). A test sends every operation with a valid credential
  and no identity and expects nine refusals.
- **In the legacy service, the grant's subject is the application, designated by its secret. The
  identity that registered it is evidence, not the subject.** It is admissible
  once, at registration, to help the person answer *is this the program I
  meant*, and it is re-checked on that connection after the person answers so
  the secret goes to the program that asked. It is then kept on the
  application's line for `rights apps`, and what held is kept on the hold for
  `rights holds`, and neither is consulted for a decision again. Deliberate: a
  grant outlives the build that earned it, and a binding that cannot cross a
  wire does not take the grant with it.
- **This holds among programs sharing one kernel and one user account.**
  Nothing here defends one account from another on the same machine; the
  Windows pipe name has no per-user component.
- **A token is a bearer credential (RFC 6750)** scoped to one right and one
  hour, issued only when the right is on the application's list. `check` is
  token introspection (RFC 7662) for a resource holder in another process.
- **In the legacy service, the service never says yes.** `ask` reports whether a grant exists;
  an answer in `asks` and `grant` are the person's acts, and the policy tool proves it is
  the person by possessing `admin.secret`, a file only that user can read.
- **Everything not on the list is absent, and absent means no.** Rights are a
  closed vocabulary; an unknown one is refused at registration.
- **A compromised application spends inside its limits and never past them.**
  Its secret yields only the rights on its own line. Revoke takes effect on
  live holds immediately.

## Today

**Native Go provider profile.** One right, `awake`, end to end on Windows 11 over a named pipe:
`openabstractions serve rights`, `rights`, `keepawake`. **Not examined: Linux, macOS** — the unix
socket listener, `systemd-inhibit` and `caffeinate` paths are written and have
never run.

It does not defend one application from another running as the same user at
the same integrity level. On Windows such a process can read the other's
secret file or its memory; `identity`'s CONTRACT.md says the same about its
answers. The boundary that holds is the one the platform enforces —
integrity level, AppContainer — and this service reports, it does not build one.

It enforces nothing inside a library. `awake` is enforceable because the OS
request is held by this process; a right over a resource the application holds
in its own process is a promise the application keeps or does not.

What may break: the pipe name belongs to the first listener
(`FILE_FLAG_FIRST_PIPE_INSTANCE`): a second rights service on the same name refuses
to start, and so does one started while a client of the previous one has not
hung up. `Close` waits for every connection, so a restart from the same process
finds the name free. `powercfg /requests` needs an elevated prompt, so the only
unelevated view of what is holding the machine awake is `rights holds`, which
sees cooperating applications only. A service restart drops every hold;
applications see `Lease.Done()` and must ask again. Registrations wait five
minutes for an answer, and a hostile client can open such waits until memory
runs out; the questions themselves live in `asks` and outlive the wait.

## Conformance

No scenario corpus; there is one implementation. The tests in `go/` send every
operation with a valid credential and no identity and expect nine refusals.

## Where it sits

Below: [abstraction-asks](https://github.com/openabstractions/abstraction-asks)
(a registration is a question a person answers),
[abstraction-identity](https://github.com/openabstractions/abstraction-identity)
(who connected), [abstraction-cas](https://github.com/openabstractions/abstraction-cas)
(the policy file) and [abstraction-watch](https://github.com/openabstractions/abstraction-watch).
Above: an application that wants a right, such as `keepawake`.

One layer of [openabstractions](https://github.com/openabstractions/abstractions).
Every layer names one thing local tools rebuild on their own; the name means the
same in each language that implements it, and the conformance scenarios are what
hold an implementation to it.

## Status

**In development.** No tagged release; the rights service, `rights` and `keepawake` run
end to end on Windows today.

## Requirements

Go 1.26 or newer. Windows 11 verified; Linux and macOS written and not run.

## Licence

Apache-2.0. See [LICENSE](https://github.com/openabstractions/abstraction-rights/blob/main/LICENSE).

### Policy administration

The generated `AuthorizationOperator` service reads bounded pages of
registered actions and rules, and conditionally sets or revokes exact rules. Configure typed-peer operator
authorization explicitly on the service; same-account applications receive no
operator permission by default. Go callers use `client.NewOperator` with the
selected `abstraction.rights/operator@1` endpoint and its context methods.

Edits carry the revision read from the policy. A conflict returns current state;
inspect it before choosing a new edit. After an uncertain reply, retry the same
expected revision or read the policy again. Clients never retry automatically.
Resources remain protected by their receiving enforcement points. See CONTRACT.md
for bounds, reconnect gaps and native awake-lease separation.

<!-- BEGIN GENERATED PERMISSION DEFINITIONS -->

## Permission definitions

Generated from the existing compiled catalogue. [RIGHTS.json](RIGHTS.json) contains the complete action/profile records, disclosure, lifecycle, first-use behavior, selector support and finite bundles.

This projection lists no action owned by Rights. Its generic seed names actions defined by other layers. Authorization, operator designation and legacy awake admission retain their existing contracts.

<!-- END GENERATED PERMISSION DEFINITIONS -->
