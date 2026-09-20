# abstraction-rights

Give one program permission to perform one named action on one resource, inspect
that decision, and revoke it without changing the application. Every protected
service checks rights at the resource boundary. A rule identifies the account,
the OS-bound program, the action and the resource; a registered action grants
nothing by itself.

Services call the generated `abstraction.rights/authorization@1` decision
service. `Require(ctx, peer, action, resource)` permits only an explicit
`permitted` result. [General decision contract](CONTRACT.md) defines trusted
enforcement points, exact rules, revision and revocation semantics. The native
registration/token/awake workflows below are separately selected interfaces.

Rights covers every protected OA action, including configuration edits, log
history, model lookup, routes, durable job submission and cancellation,
credential use, inference, application discovery and activation, storage, asks
and keep-awake holds.

Operators inspect and change exact rules with the generated operator client or
CLI:

```console
openabstractions rights list --json
openabstractions rights decide --action <action> --resource <resource>
openabstractions rights grant --program /absolute/path/to/app \
  --action <action> --resource <resource> --why "operator choice"
```

`grant --for downloads` and `grant --for inference` expand documented bundles
into exact rules and report every rule that landed. Resource services remain the
enforcement points and return their own typed `forbidden` or `unavailable`
outcomes.

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
| job Submit | `abstraction.job/acceptance.submit` | `abstraction.job/acceptance@1` | installed |
| job operator ListAccountWork | `abstraction.job/inventory.read` | `abstraction.job/acceptance@1` | installed |
| job operator CancelOperation | `abstraction.job/acceptance.cancel` | `abstraction.job/acceptance@1` | installed |
| credentials manage, read, apply | `abstraction.credentials/holder.manage`, `holder.read`, `apply` | `account`, `credential:<name>` | installed |
| inference complete, host management, key issue, audit read | `abstraction.inference/complete`, `host.manage`, `key.issue`, `audit.read` | `host:<name>`, `account` | installed |
| asks application Ask | `abstraction.asks/question.ask` | `account` | installed |
| applications Register, Remove | `abstraction.facade/application.manage` | `account` | installed |
| applications Announce, Withdraw | `abstraction.facade/application.announce` | `app:<descriptor>` | installed |
| applications Observe | `abstraction.facade/application.read` | `app:<descriptor>` | installed |
| applications Activate | `abstraction.facade/application.activate` | `app:<descriptor>` | installed |
| provider registry changes | `abstraction.facade/provider.manage` | `account` | installed |
| storage inventory source registration | `abstraction.storage/inventory.provide` | `store:<name>` | installed |
| storage Open | `abstraction.storage/content.read` | content digest | library |
| storage Begin, Append, Commit | `abstraction.storage/content.write` | content digest | library |
| storage change Observe, List | `abstraction.storage/content.observe` | `abstraction.storage/changes` | library |
| storage Remove | `abstraction.storage/content.remove` | `store:<name>` | library |

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
config edit, history, model lookup on each registry, router inventory and
routes, job submit, cancel and account inventory, credentials `holder.manage`
and `holder.read`, and inference `host.manage` and `key.issue`, and records each
in `rights/defaults-applied`. A rule the person revoked is never written again.
Applications hold no rule by installation. A person grants one with
`openabstractions rights grant`, `rights grant --for downloads|inference`, the
Panel's Rights and Explore sections, or by answering the question the runtime
asks when a job submit, model lookup or inference complete first decides
`not_granted`.

**In development.** No tagged release; `rightsd`, `rights` and `keepawake` run
end to end on Windows today.

A right a person has granted to an application is held by a service on the
application's behalf, so revoking the right releases the machine the same
second, and no service ever says yes on its own.

## The problem

Every application that wants to hold the machine awake asks the operating
system itself, and nothing on the machine can say who is holding it or take the
hold away. This is a local service that issues tokens for rights a person has
granted, and a tool that edits the grants. The first right is `awake`: may this
application hold the machine awake. The service holds the OS request on the
application's behalf, so revoking the right releases the machine the same
second.

## Words

| word | meaning |
|---|---|
| **right** | one name from a closed vocabulary; the first is `awake`. Everything not on the list is absent, and absent means no |
| **registration** | the device authorization grant (RFC 8628): an application connects, says its name and the rights it wants, and waits for a person |
| **grant** | a person's act; its subject is the application, designated by its secret |
| **token** | a bearer credential (RFC 6750) scoped to one right and one hour |
| **hold** | a right in use, kept by the service on the application's behalf |
| **check** | token introspection (RFC 7662) for a resource holder in another process |

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

    go build -o bin/ ./go/cmd/...
    bin/asksd                        # registrations are questions; see abstraction-asks
    bin/rightsd                      # foreground; prints where it listens

In another shell:

    bin/keepawake encoding a long video
      keepawake is not registered; asking the service
        a person has to answer:  asks pending  then  asks answer <id> allow

    bin/asks pending
      5a20a0  keepawake wants to: awake
              asked 1s ago via ...\rightsd.exe  ...  no signature
              for ...\keepawake.exe  ...  no signature, on the word of the asker
              answers: allow, refuse, never
    bin/asks answer 5a20a0 allow

    bin/rights holds
      a62cca76  keepawake   holds awake   for 4s: encoding a long video
    bin/rights revoke keepawake awake
      (keepawake prints: the hold was taken away)

`rights apps` lists every application and what it may do. `grant`, `revoke`
and `forget` do what they say. A registration answered *never* is refused
without asking, for as long as that answer stands. Policy lives in `policy.json` under
`os.UserConfigDir()/openabstractions/rights`, or `-state <dir>` on both
programs.

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

**Authority is designation, not identity.** This is OAuth's shape, and the
three pieces map onto it directly.

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
- **The grant's subject is the application, designated by its secret. The
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
- **The service never says yes.** `ask` reports whether a grant exists;
  an answer in `asks` and `grant` are the person's acts, and the policy tool proves it is
  the person by possessing `admin.secret`, a file only that user can read.
- **Everything not on the list is absent, and absent means no.** Rights are a
  closed vocabulary; an unknown one is refused at registration.
- **A compromised application spends inside its limits and never past them.**
  Its secret yields only the rights on its own line. Revoke takes effect on
  live holds immediately.

## Today

**Native Go provider profile.** One right, `awake`, end to end on Windows 11 over a named pipe:
`rightsd`, `rights`, `keepawake`. **Not examined: Linux, macOS** — the unix
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
(`FILE_FLAG_FIRST_PIPE_INSTANCE`): a second `rightsd` on the same name refuses
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

## Requirements

Go 1.26 or newer. Windows 11 verified; Linux and macOS written and not run.

## Licence

Apache-2.0. See [LICENSE](https://github.com/openabstractions/abstraction-rights/blob/main/LICENSE).

### Policy administration

The generated `AuthorizationOperator` service reads bounded catalogue/rule pages
and conditionally sets or revokes exact rules. Configure typed-peer operator
authorization explicitly on the service; same-account applications receive no
operator permission by default. Go callers use `client.NewOperator` with the
selected `abstraction.rights/operator@1` endpoint and its context methods.

Edits carry the revision read from the policy. A conflict returns current state;
inspect it before choosing a new edit. After an uncertain reply, retry the same
expected revision or read the policy again. Clients never retry automatically.
Resources remain protected by their receiving enforcement points. See CONTRACT.md
for bounds, reconnect gaps and native awake-lease separation.
