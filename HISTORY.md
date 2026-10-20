# abstraction.rights history

Prior art, provenance and what was tested for [CONTRACT.md](CONTRACT.md),
kept out of the contract itself per `research/vocabulary/DECISION.md` S7.

## Why the shape changed, 2026-09-23

The page carried no rule ids before this date; every obligation sat in prose
a test could not cite by name. `research/vocabulary/RENAME-PLAN.md` "rights
(5 steps)" converted it to the `[RIGHTS-A…]` / `[RIGHTS-R…]` / `[RIGHTS-O…]`
/ `[RIGHTS-E…]` id families, added the `Binds:` line, the RFC 8174
boilerplate, the letter and prose-to-wire tables, and gathered the
Divergences and Bounds sections that were previously scattered through the
prose. No described behaviour changed in this pass except the one line below.

## Operator Allow completion, 2026-10-04

The owner required the operator Allow lapse fix before 0.4. A permit could
land and be revoked before any successful application retry, leaving its
answered question replaying until Dismiss. `ApplyFirstUseAllow` carries the
actual question ID to rights; trusted composition pins the runtime Book,
derives the complete pair and commits durable completion with its permits.
An answered Allow whose write never landed retains explicit Retry.
`rights-decisions@4` reads canonical @2/@3 and retains proofs through every
rights writer. Ordinary setters and asks AnswerQuestion preserve their
published meanings. The focused source regressions cover immediate revoke or
expiry before retry, discarded postcommit reply and reload, failed writes, full
pairs, exact-ID release, contextual lock waits and bounded orphan pruning.

## Decision explanations, 2026-10-08

The Panel's app page had matched an app's rules against the defaults by exact
strings, missing typed Blocks and a rule saved under another spelling of the
same program (an 8.3 alias), and mapping every-resource defaults by hand
(Panel review of `a596d6c25`). RIGHTS-O14 gives operators `ExplainFor`: the
legacy decision returns its deciding step from the one evaluation
(`legacyOperationExplained`), so the decision and its explanation cannot
differ. Regressions: each step, an excluded script host, a typed Block over an
own permit, a short-alias Block, no revision change, the wire round trip and
its refusal shape.

## Account-wide defaults, 2026-10-07

The owner ruled that every app may register itself, ask, announce, notify and
download by default, each default with its own switch, and that a shared
interpreter never receives one (VISION 2026-10-07). RIGHTS-R22 and RIGHTS-O13
put the defaults in the decision policy, after each program's own rule, so a
Block for one app wins and a removed rule never returns; no rule is written.
`rights-decisions@7` stores turned switches; @2..@6 stay readable. Phase 1
had weighed write-once default rules recorded in the installation marker;
switches make that unnecessary
(`research/release-0.4.0/planned/default-policy-decisions.md`). The focused
regressions cover each default, Block and permit precedence, expiry, script
host and foreign-account exclusion, switch off/on across reload, stale and
unconfigured edits, outage, the profile boundary and the operator wire.

## Prior art

Decide/DecideFor's decision vocabulary (`permitted`, `denied`, `not_granted`,
`unknown_action`) follows XACML's permit/deny shape rather than this
project's own `outcome` word; [RIGHTS-E1] and the Divergences section on
CONTRACT.md record why, per `research/vocabulary/DECISION.md` D51, D52. The
native registration/token/hold workflow README.md describes follows RFC 8628
(device authorization) and RFC 6750 (bearer tokens).

## Superseded: the awake lease sentence, resource review F10

`research/reviews/resource-2026-09-23.md` finding F10: CONTRACT.md said
"Existing registration secrets, bearer tokens and connection-owned awake
leases retain their native service and persistence unchanged", two
paragraphs before saying the hold's record is read from the resource lease
book's `awake` rows — the two sentences disagreed about what "unchanged"
covered. `abstraction-resource` CONTRACT.md RES-A1 already stated the
correct split: the record moved under `leases@1`, the lifetime did not.

CONTRACT.md now states only the narrower, correct claim, in [RIGHTS-R12]:
"the platform request and its connection lifetime stay native." The "Not
built" section's awake-lease bullet was reworded to agree with RES-A1: what
is unbuilt is the request's own lifetime moving off the native connection,
not the record, which already lives in the resource lease book
([RIGHTS-R14]).

## The class-scoped meta-rule, 2026-10-03

[RIGHTS-R16] implements part 4 of the 0.4.0 rights slice
(`research/rights-model/PROPOSAL.md` §15; VISION 2026-10-03). The owner
later chose Stop with optional cleanup: withdrawing the meta-rule ends
future answers; the Panel's unchecked cleanup removes current permits
whose `set_by` is that answerer in the same edit. Otherwise each permit
keeps its stamped expiry. Applied answers renew the enrollment and permits
that shared the previous expiry, so idle lapse ends those together.
`RevokeAnswerPermits` removes only still-current effects of the selected
question. A private question ID in the version 3 file prevents an old
Undo from deleting a same-millisecond replacement; version 2 canonical
files remain readable and migrate on write. Paired first-use actions now
use one rights edit, so a conflicting read never leaves a write grant.

## A revoke ends the wake lease, 2026-10-07

Revoking `awake` (the alias of `abstraction.resource/hold` on `awake`) in
the versioned decision policy left the program's acquired wake lease in
the resource service until the program released it; only the legacy
service's own connection-owned hold closed on a revoke. RIGHTS-R13 now
requires the policy to report each committed change before the edit
returns. `DecisionPolicy.OnChange` is called from the two commit paths
every writer goes through (`change`, `changeContext`), and the runtime
composes it with the resource service's `Book.RecheckWake`
(abstraction-resource RES-A1). An expiry commits nothing, so the resource
host decides again on its clock as well. Test:
`go/decision_change_test.go`.

## Every grant held past its call, 2026-10-07

The survey after the wake fix found three more grants that outlived a
revoke: card leases renewed without a decision, live inference sessions
decided once at `StartLive`, and durable inference jobs polling with the
plan's credential headers (TODO "Live grants outlive revocation"). One
`OnChange` function could serve only one owner, and a later call replaced
the resource book's. RIGHTS-R23 now states the rule for every owner, and
RIGHTS-R13 points at it. `OnChange` adds a function and returns its
removal; every added function runs after each committed change, in the
order added. The runtime adds the resource book's `Book.Recheck`
(RES-L7) and the inference provider's `Provider.Recheck` (INF-A6). Test:
`go/decision_change_test.go` (two functions, one removed, the other still
called).

## Measured

`TestMetaRuleDecisionCostAmongHundredRules` (Windows, 2026-10-03): reading a
holder's meta-rule among 100 rules took 301 µs per decision, beside 367 µs
for `TestDecisionCostAmongHundredRules` in the same run. `abstraction-resource`
CONTRACT.md carries the awake-hold measurement this page's Divergences
section points at.

## Tested

README.md's Conformance section: no scenario corpus; there is one
implementation, and the tests in `go/` send every operation with a valid
credential and no identity and expect nine refusals.

---

Back to [CONTRACT.md](CONTRACT.md).
