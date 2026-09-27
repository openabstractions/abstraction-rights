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

## Measured

None recorded for this module; `abstraction-resource` CONTRACT.md carries
the awake-hold measurement this page's Divergences section points at.

## Tested

README.md's Conformance section: no scenario corpus; there is one
implementation, and the tests in `go/` send every operation with a valid
credential and no identity and expect nine refusals.

---

Back to [CONTRACT.md](CONTRACT.md).
