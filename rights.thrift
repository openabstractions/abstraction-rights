namespace * abstraction.rights.api

// Shared rights concepts; native binding supplements are explicit below.
encoding json {
 escape="minimal"
 indent="2"
 map_keys="utf8-bytes"
 numbers="integer-decimal"
 opaque="verbatim"
 terminator="newline"
 duplicate_keys="refuse"
 depth_limit="64"
}
refusal {
 1: malformed(stage="grammar")
 2: bad_string(stage="grammar")
 3: number_spelling(stage="grammar")
 4: wrong_type(stage="grammar")
 5: depth_exceeded(stage="grammar")
 6: duplicate_key(stage="grammar")
 7: duplicate_field(stage="structure")
 8: unknown_field(stage="structure")
 9: missing_field(stage="structure")
 10: bad_enum(stage="structure")
 11: trailing_bytes(stage="document")
}
struct Request {
 1: required string op
 2: optional string name(omit="absent")
 3: optional list<string> rights(omit="zero")
 4: optional string secret(omit="absent")
 5: optional string token(omit="absent")
 6: optional string right(omit="absent")
 7: optional string why(omit="absent")
 8: optional string app(omit="absent")
 9: optional string admin(omit="absent")
}(document="true",unknown_fields="refuse",doc="Existing rights request concepts. Secret/token/admin remain credential inputs checked by the service; request text never substitutes for native peer identity. This descriptor does not replace the existing handwritten line transport.")
struct AppMetadata {
 1: required string id
 2: required string name
 3: required list<string> rights
 4: required string registered
}(unknown_fields="refuse",doc="Own application registration fields; registered uses the existing RFC3339 time representation. Native App additionally carries identity.listen.Seen observation evidence.")
struct HoldMetadata {
 1: required string app
 2: required string name
 3: required string right
 4: required string why
 5: required string since
}(unknown_fields="refuse",doc="Own held-right fields; since uses existing RFC3339 time representation. Native Hold also carries Seen. The live Lease is connection-owned and cannot be recreated from these fields.")
struct ResponseMetadata {
 1: optional string code(omit="absent")
 2: optional string error(omit="absent")
 3: optional string secret(omit="absent")
 4: optional string token(omit="absent")
 5: optional string expires(omit="absent")
 6: optional AppMetadata app(omit="absent")
 7: optional string right(omit="absent")
 8: optional list<AppMetadata> apps(omit="zero")
 9: optional list<HoldMetadata> holds(omit="zero")
}(unknown_fields="refuse",doc="Own response fields projected without native Seen evidence. Any nonempty code/error is refusal, including unknown codes. This is a common descriptor, not a replacement legacy Response codec or generated service client.")
const list<string> operations = ["register", "ask", "hold", "check", "apps", "grant", "revoke", "forget", "holds"]
const list<string> known_rights = ["awake"]
const list<string> refusal_codes = ["internal", "invalid_request", "caller_refused", "unknown_operation", "not_administrator", "pending", "denied", "denied_permanently", "unsupported_hold", "platform_refused", "unknown_app", "unknown_right", "not_granted", "bad_secret", "bad_token"]

struct Subject {
 1: required string account
 2: required string program
}(unknown_fields="refuse",doc="Account identifier and normalized absolute executable path. This serialized subject is an assertion by an explicitly authorized enforcement point. It contains no proof or verified flag and cannot authorize its own use. Direct decisions derive their subject from native receiving Program evidence.")
enum DecisionOutcome {
 1: permitted
 2: denied
 3: not_granted
 4: unknown_action
 5: invalid
 6: forbidden
 7: unavailable
}(unknown="refuse",reader="act")
struct Decision {
 1: required DecisionOutcome outcome
 2: optional string policy_revision(omit="absent")
}(unknown_fields="refuse",doc="A point-in-time policy decision. Only permitted allows an enforcement point to proceed. denied is an explicit exact deny; not_granted has no unexpired exact rule; unknown_action is outside the current catalogue. Evaluated permitted/denied/not_granted/unknown_action decisions carry an opaque revision observed with that decision. Errors carry none. No lease, token, cached permission lifetime or human consent is conveyed.")
service Authorization {
 Decision Decide(1:string action,2:string resource)(doc="Evaluate the bound receiving account/program against an exact action/resource rule. This result is advisory to the caller; resource services query the decision point themselves.")
 Decision DecideFor(1:Subject subject,2:string action,3:string resource)(doc="Evaluate a subject assertion only when the receiving peer is explicitly authorized as an enforcement point for this action/resource. Same account alone grants no relay authority. The designated enforcer is trusted to supply its actual bound subject. Nil or refusing enforcer policy yields forbidden before policy lookup.")
}(wire_name="abstraction.rights/authorization@1",doc="General exact-rule authorization decision point with a bounded, registrable catalogue and persistence. Unknown, absent, unspecified, expired, failed and refused decisions never permit. Explicitly authorized operator configuration registers actions and grants/revokes exact rules; no serialized awake lease is introduced.")
// The OA seed of the action catalogue. A policy host starts from the seed it is
// configured with; resource services register further <owner>/<name> actions
// through RegisterAction or the native registration API.
const list<string> resource_actions = ["abstraction.storage/content.read", "abstraction.storage/content.write", "abstraction.job/acceptance.submit", "abstraction.job/acceptance.cancel", "abstraction.config/user.replace", "abstraction.logging/history.read", "abstraction.model/lookup", "abstraction.router/inventory.read", "abstraction.router/route", "abstraction.storage/content.observe", "abstraction.storage/content.remove"]


struct PolicyRule {
 1: required Subject subject
 2: required string action
 3: required string resource
 4: required bool permit
}(unknown_fields="refuse",doc="One exact policy rule. Subject is the administrative target, never caller proof. Account is 1..128 UTF-8 bytes; program is a normalized absolute path up to 4096 bytes; action is 1..128 bytes and belongs to the current catalogue; resource is 1..1024 bytes. All strings exclude control characters. permit=false is an explicit deny; revocation removes the exact rule and restores not_granted.")
enum PolicyPageOutcome {
 1: page
 2: gap
 3: invalid
 4: forbidden
 5: unavailable
}(unknown="refuse",reader="act")
struct PolicyPage {
 1: required PolicyPageOutcome outcome
 2: required string revision
 3: required list<string> catalog
 4: required list<PolicyRule> rules
 5: required string next
 6: required bool complete
}(unknown_fields="refuse",doc="Latest-policy enumeration: 1..64 requested rules and at most 256 KiB encoded reply, including catalogue, cursor and indentation. Catalogue is the configured seed plus registered actions, sorted, bounded to 64 actions of 128 bytes. Rules are every retained rule, including expired rules the next write removes; ReadRule reports expiry and provenance. Page carries the exact durable content revision. A noncomplete page has a nonempty next cursor. Refusals have empty revision/catalog/rules/next and complete=false. Cursors are at most 256 UTF-8 bytes, bind receiving account/program and host epoch/revision, and return gap after change/restart/scope mismatch. Restart from empty cursor. No immutable multipage snapshot or historical change replay is promised.")
enum PolicyEditOutcome {
 1: applied
 2: conflict
 3: invalid
 4: forbidden
 5: unavailable
}(unknown="refuse",reader="act")
struct PolicyEdit {
 1: required PolicyEditOutcome outcome
 2: required string revision
 3: optional PolicyRule current(omit="absent")
}(unknown_fields="refuse",doc="Applied/conflict carry the revision and optional exact current rule observed inside the conditional edit; absent current means no exact rule. Other outcomes carry no revision/current. A stale expected revision always conflicts, including when the desired state happens to match. No-op edits at the matching revision preserve it without writing. A lost reply is uncertain: retrying the same expected revision cannot overwrite a later edit, and may conflict after a successful original change. Reconcile the returned current state or fresh history before choosing another edit. This is optimistic concurrency, not an exactly-once mutation journal.")
struct RuleRecord {
 1: required PolicyRule rule
 2: required Subject set_by
 3: required string set_at
 4: required string why
 5: required string expires
}(unknown_fields="refuse",doc="One exact rule with its provenance. set_by is the subject the rights service established for the party that set the rule: the operator's receiving Program evidence, or the service's own account and executable for native edits. The request never supplies it. set_at is the service's UTC edit time as RFC 3339 with milliseconds. why is the operator's reason of 0..256 UTF-8 bytes without control characters. expires is empty for a rule without expiry, or the UTC instant, in the same format, from which the rule decides nothing.")
enum RuleReadOutcome {
 1: found
 2: expired
 3: unknown
 4: invalid
 5: forbidden
 6: unavailable
}(unknown="refuse",reader="act")
struct RuleRead {
 1: required RuleReadOutcome outcome
 2: required string revision
 3: optional RuleRecord record(omit="absent")
}(unknown_fields="refuse",doc="found and expired carry the revision and the exact record. expired names a retained rule at or past its expiry; it decides nothing and the next policy write removes it. unknown carries the revision and no record. invalid, forbidden and unavailable carry neither.")
struct CatalogEntry {
 1: required string action
 2: required Subject registered_by
 3: required string registered_at
}(unknown_fields="refuse",doc="One registered catalogue action. Seeded actions have no entry. registered_by is the subject the rights service established for the registering party: the operator's receiving Program evidence, or the service's own account and executable for native registration. registered_at is the service's UTC time as RFC 3339 with milliseconds.")
enum ActionEditOutcome {
 1: applied
 2: conflict
 3: unknown
 4: invalid
 5: exhausted
 6: forbidden
 7: unavailable
}(unknown="refuse",reader="act")
struct ActionEdit {
 1: required ActionEditOutcome outcome
 2: required string revision
 3: optional CatalogEntry current(omit="absent")
}(unknown_fields="refuse",doc="applied, conflict and unknown carry the revision observed inside the conditional edit. applied and conflict carry the action's registration entry when one exists; a seeded or retired action has none. unknown means RetireAction named an action outside the catalogue. exhausted means the catalogue already holds 64 actions. invalid, exhausted, forbidden and unavailable carry no revision or entry. A stale expected revision always conflicts.")
service AuthorizationOperator {
 PolicyPage ListPolicy(1:string cursor,2:i64 limit)(doc="Read bounded current rules and catalogue under explicit operator authorization. Every continuation rechecks authorization; no enumeration session is retained for disconnected/slow callers.")
 PolicyEdit SetRule(1:string expected_revision,2:PolicyRule rule)(doc="Atomically compare the expected durable revision and set one exact permit/deny rule with no expiry and an empty reason. Revision is bounded to 128 UTF-8 bytes. Operator context and authority are checked again inside the atomic edit after lock waiting. The rule records the operator's established subject and the edit time. An unexpired rule with the same permit is a no-op that keeps its record. Uncatalogued actions and malformed targets are invalid; no resource permission is inferred from the operator request itself.")
 PolicyEdit RevokeRule(1:string expected_revision,2:Subject subject,3:string action,4:string resource)(doc="Atomically remove one exact rule if the revision matches. The next fresh decision observes successful revocation. A failed/uncertain reply claims no successful revocation; inspect current state before another intent. It does not cancel an existing connection-owned awake lease.")
 PolicyEdit SetRuleFor(1:string expected_revision,2:PolicyRule rule,3:i64 ttl_ms,4:string why)(doc="As SetRule, recording why and an expiry ttl_ms after the service's edit time. ttl_ms 0 sets no expiry; otherwise it is 1..31536000000. why is 0..256 UTF-8 bytes without control characters. A retained rule with the same permit, reason and expiry is a no-op; any other difference writes, including a new expiry.")
 RuleRead ReadRule(1:Subject subject,2:string action,3:string resource)(doc="Read one exact rule with its provenance and expiry under operator authorization, rechecked after the read.")
 ActionEdit RegisterAction(1:string expected_revision,2:string action)(doc="Add an action named <owner>/<name> to the catalogue. owner is 1..64 bytes and name 1..63 bytes of lowercase ASCII letters, digits, '.', '_' and '-', each beginning with a letter or digit. Registering an action already in the catalogue applies without writing. A registration records the operator's established subject and the service time. Registration grants nothing: decisions on the action read not_granted until a rule exists.")
 ActionEdit RetireAction(1:string expected_revision,2:string action)(doc="Remove a registered action and every rule naming it. Retiring a seeded action is invalid. Retiring an action outside the catalogue is unknown. Decisions on a retired action read unknown_action.")
}(wire_name="abstraction.rights/operator@1",doc="Explicitly authorized administration of the configured decision policy: catalogue registration and retirement, exact rules with expiry and provenance. Receiving same-account Program proof plus a trusted typed-peer operator callback is required; nil refuses. Policy denial is forbidden; callback/storage failure is unavailable. No caller credential, verified flag or provider path is accepted. Resource services remain the receiving enforcement points. Legacy bearer and awake lease behavior is separate.")
