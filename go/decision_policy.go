package rights

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	cas "github.com/openabstractions/abstraction-cas/go"
	identity "github.com/openabstractions/abstraction-identity"
	wire "github.com/openabstractions/abstraction-rights/go/abstraction/rights/api"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// DecisionProfile adds account-wide default switches (RIGHTS-R22); @6 added typed
// selector rules and frozen bundle origins. Versions 2..6 remain readable; a
// real edit/canonicalization writes the current version.
const DecisionProfile = "rights-decisions@7"
const typedDecisionProfile = "rights-decisions@6"
const describedDecisionProfile = "rights-decisions@5"
const completedAnswerDecisionProfile = "rights-decisions@4"
const answerIdentityDecisionProfile = "rights-decisions@3"
const previousDecisionProfile = "rights-decisions@2"
const MaxDecisionBytes = 4 << 20
const MaxDecisionRules = 4096
const MaxDecisionActions = 64

// MaxRuleTTL bounds a rule's expiry after its edit time.
const MaxRuleTTL = 365 * 24 * time.Hour

// MaxRuleWhy bounds the operator's recorded reason in bytes.
const MaxRuleWhy = 256

// StampFormat is the UTC service time carried by provenance and expiry.
const StampFormat = "2006-01-02T15:04:05.000Z"

// ErrCatalogueFull reports a registration beyond MaxDecisionActions.
var ErrCatalogueFull = errors.New("rights: catalogue holds the maximum number of actions")

type decisionRule struct {
	Subject    wire.Subject `json:"subject"`
	Action     string       `json:"action"`
	Resource   string       `json:"resource"`
	Permit     bool         `json:"permit"`
	SetBy      wire.Subject `json:"set_by"`
	SetAt      string       `json:"set_at"`
	Why        string       `json:"why,omitempty"`
	Expires    string       `json:"expires,omitempty"`
	QuestionID string       `json:"answer_question_id,omitempty"`
}
type registeredAction struct {
	Action string       `json:"action"`
	By     wire.Subject `json:"by"`
	At     string       `json:"at"`
}
type decisionFile struct {
	Profile                string                 `json:"profile"`
	Actions                []registeredAction     `json:"actions"`
	Rules                  []decisionRule         `json:"rules"`
	AppliedOperatorAnswers []string               `json:"applied_operator_answers,omitempty"`
	Descriptions           []publishedDescription `json:"descriptions,omitempty"`
	SelectorRules          []selectorRule         `json:"selector_rules,omitempty"`
	BundleOrigins          []storedBundleOrigin   `json:"bundle_origins,omitempty"`
	AppliedTypedAnswers    []string               `json:"applied_typed_answers,omitempty"`
	DefaultSwitches        []defaultSwitch        `json:"default_switches,omitempty"`
}

// profileVersion is the version of a readable decision profile, 0 for any
// other spelling.
func profileVersion(profile string) int {
	switch profile {
	case DecisionProfile:
		return 7
	case typedDecisionProfile:
		return 6
	case describedDecisionProfile:
		return 5
	case completedAnswerDecisionProfile:
		return 4
	case answerIdentityDecisionProfile:
		return 3
	case previousDecisionProfile:
		return 2
	}
	return 0
}

// DecisionPolicy owns a separate service-only state file. Native Set/Revoke and
// RegisterAction are operator authority, never application methods. The catalogue
// is the configured seed plus actions registered in the file.
type DecisionPolicy struct {
	path   string
	seed   []string
	native wire.Subject
	// Clock supplies service time for provenance and expiry. Nil uses time.Now.
	// Assign before the policy is shared.
	Clock func() time.Time
	// Definitions is the trusted immutable full-key catalogue. Configure at load
	// with LoadDecisionPolicyWithDefinitions; never replace it while serving.
	Definitions *DefinitionCatalog
	// StateRequired makes an absent state file an outage: decisions read
	// unavailable, and edits and registrations refuse. A host sets it once its
	// installation has created the file, so a removed file never reads as an
	// empty policy. Assign before the policy is shared.
	StateRequired bool
	// MetaHolder, when set, refuses a program as the holder of a class-scoped
	// meta-rule (RIGHTS-R16). A host names its operator programs here, and
	// any other program whose own rules optional cleanup must never take; the
	// service's own program is always refused. Assign before the policy is
	// shared.
	MetaHolder func(wire.Subject) error
	// defaults, defaultAccount and defaultExcluded are the account-wide
	// defaults ConfigureDefaults set (RIGHTS-R22).
	defaults        []AccountDefault
	defaultAccount  string
	defaultExcluded func(wire.Subject) bool
	// stored holds stored programs' file identities for decisions, and
	// decoded the last state read.
	stored  storedKeys
	decoded decodedState
	// changed holds the functions OnChange added, each called after every
	// committed change; changedMu guards the slice, never a call.
	changedMu sync.Mutex
	changed   []*func()
}

// OnChange adds changed, called after every change this policy commits, a
// revoke, Block, removal, switch or grant alike, before the edit returns
// (RIGHTS-R23). Each owner that keeps something alive under a decision adds
// its own function to end what a revoked rule kept: the resource service's
// leases, inference's running operations. The functions run in the order they
// were added, on the editing caller's goroutine, and must not edit this
// policy. A rule that expires commits nothing: whoever keeps something under a
// rule also decides it again on a clock. The returned function removes
// changed for every change committed after it returns; it does not wait for a
// call already running, so an owner that closes after removing its function
// tolerates one last call. A nil changed adds nothing.
func (p *DecisionPolicy) OnChange(changed func()) (remove func()) {
	if changed == nil {
		return func() {}
	}
	entry := &changed
	p.changedMu.Lock()
	p.changed = append(p.changed, entry)
	p.changedMu.Unlock()
	return func() {
		p.changedMu.Lock()
		defer p.changedMu.Unlock()
		p.changed = slices.DeleteFunc(slices.Clone(p.changed), func(e *func()) bool { return e == entry })
	}
}

// committed calls every OnChange function after a change that succeeded.
func (p *DecisionPolicy) committed(err error) error {
	if err == nil {
		p.changedMu.Lock()
		changed := p.changed
		p.changedMu.Unlock()
		for _, call := range changed {
			(*call)()
		}
	}
	return err
}

// ErrDecisionStateMissing reports an absent state file under StateRequired.
var ErrDecisionStateMissing = errors.New("rights: decision state is missing")

func boundedDecisionString(v string, max int) bool {
	return len(v) > 0 && len(v) <= max && utf8.ValidString(v) && strings.IndexFunc(v, unicode.IsControl) < 0
}
func validWhy(v string) bool {
	return v == "" || boundedDecisionString(v, MaxRuleWhy)
}

// NormalizeDecisionSubject also canonicalizes a plain program path: a rule
// granted or matched against a short DOS 8.3 launch alias compares equal to
// the same file's long spelling (identity.CanonicalProgramPath), on both the
// stored side (grant, revoke, register/retire) and the query side (decide,
// read). A path CanonicalProgramPath cannot resolve, including one naming no
// existing file, comes back unchanged, so a different file still refuses.
func NormalizeDecisionSubject(s wire.Subject) (wire.Subject, error) {
	if strings.HasPrefix(s.Program, identity.PackagedProgramPrefix) {
		if !boundedDecisionString(s.Account, 128) || !identity.ValidSubjectProgram(s.Program) {
			return wire.Subject{}, errors.New("rights: invalid subject")
		}
		return s, nil
	}
	if !boundedDecisionString(s.Account, 128) || !boundedDecisionString(s.Program, 4096) || !filepath.IsAbs(s.Program) {
		return wire.Subject{}, errors.New("rights: invalid subject")
	}
	s.Program = identity.NormalizeSubjectProgram(s.Program)
	return s, nil
}

// ErrUnresolvedShortName refuses a rule edit whose program path keeps a short
// (8.3) alias that names no existing file or folder. Once a file appears
// there its canonical spelling differs, and a rule stored under the alias
// would match nothing: a deny would be lost.
var ErrUnresolvedShortName = errors.New("rights: the program path names a short (8.3) alias that does not exist; name the program by its long path")

// writableSubject is NormalizeDecisionSubject for a subject an edit stores:
// it also refuses a spelling identity.UnresolvedShortName reports.
func writableSubject(s wire.Subject) (wire.Subject, error) {
	n, e := NormalizeDecisionSubject(s)
	if e != nil {
		return n, e
	}
	if identity.UnresolvedShortName(n.Program) {
		return wire.Subject{}, fmt.Errorf("%w: %s", ErrUnresolvedShortName, n.Program)
	}
	return n, nil
}

// validStoredSubject reports whether s is a subject as the state file stores
// one: a bounded account and a valid subject program
// (identity.ValidSubjectProgram: a package family, or a clean absolute path).
// Every edit canonicalizes its subjects before writing (writableSubject), the
// policy canonicalizes the whole file once when it loads
// (LoadDecisionPolicy), and every decision canonicalizes its query, so a read
// resolves only stored spellings shaped like a short alias
// (canonicalizeStored); every other stored subject is checked by syntax, with
// no filesystem call per rule.
func validStoredSubject(s wire.Subject) bool {
	return boundedDecisionString(s.Account, 128) && boundedDecisionString(s.Program, 4096) && identity.ValidSubjectProgram(s.Program)
}

// canonicalizeStored brings the stored subjects of f to their canonical
// spelling: every one when all is set, else those spelled like a short
// (8.3) alias, which a file created since the write can make resolve. Two
// rules that then name the same target merge, and a deny wins over a permit,
// so a deny is never lost to a spelling change. It reports whether anything
// changed.
func canonicalizeStored(f *decisionFile, all bool) bool {
	changed := false
	fix := func(s *wire.Subject) {
		if !all && !identity.HasShortNameComponent(s.Program) {
			return
		}
		if n, e := NormalizeDecisionSubject(*s); e == nil && n != *s {
			*s, changed = n, true
		}
	}
	for i := range f.Actions {
		fix(&f.Actions[i].By)
	}
	for i := range f.Descriptions {
		fix(&f.Descriptions[i].Description.FeatureApp)
		fix(&f.Descriptions[i].By)
	}
	for i := range f.Rules {
		fix(&f.Rules[i].Subject)
		fix(&f.Rules[i].SetBy)
	}
	if changed || all {
		merged := mergeRules(f.Rules)
		changed = changed || len(merged) != len(f.Rules)
		f.Rules = merged
	}
	return changed
}

// sameTarget reports whether r is a rule on the target (s, action, resource):
// the same account, action and resource exactly, and the same program as
// identity.SameNormalizedSubjectProgramKeyed compares two stored spellings:
// byte-equal names are one program; otherwise file identity decides when
// both exist on a local drive, and the name rule when either does not
// (RIGHTS-R10). Stored spellings stay as written. Account, action and
// resource are compared first and the bytes of the names next, so only a
// rule on the target's own action and resource whose name differs asks key
// for a file identity.
func sameTarget(r decisionRule, s wire.Subject, action, resource string, key programKeys) bool {
	return r.Subject.Account == s.Account && r.Action == action && r.Resource == resource &&
		identity.SameNormalizedSubjectProgramKeyed(r.Subject.Program, s.Program,
			func() string { return key(r.Subject.Program) }, func() string { return key(s.Program) })
}

// programKeys gives a program's file identity (identity.ProgramKey), "" for
// none.
type programKeys func(program string) string

// keyOnce is a programKeys that reads each program's file identity once, for
// one pass of an edit or a merge over the rules.
func keyOnce() programKeys {
	read := map[string]string{}
	return func(program string) string {
		key, ok := read[program]
		if !ok {
			key = identity.ProgramKey(program)
			read[program] = key
		}
		return key
	}
}

// StoredKeyReuse bounds how long a decision reuses a stored program's file
// identity within one policy revision (RIGHTS-R10). A program installed,
// removed or replaced after a reading is seen by name at once and by file
// identity within this time.
const StoredKeyReuse = 2 * time.Second

// storedKeys holds the file identities of stored rule programs for one
// policy revision, by stored spelling, each reused for StoredKeyReuse.
type storedKeys struct {
	mu       sync.Mutex
	revision string
	keys     map[string]storedKey
}

type storedKey struct {
	key  string
	read time.Time
}

func (c *storedKeys) key(revision, program string) string {
	now := time.Now()
	c.mu.Lock()
	if c.revision != revision || c.keys == nil {
		c.revision, c.keys = revision, map[string]storedKey{}
	}
	if k, ok := c.keys[program]; ok && now.Sub(k.read) < StoredKeyReuse {
		c.mu.Unlock()
		return k.key
	}
	c.mu.Unlock()
	key := identity.ProgramKey(program)
	c.mu.Lock()
	if c.revision == revision {
		c.keys[program] = storedKey{key: key, read: now}
	}
	c.mu.Unlock()
	return key
}

// decisionKeys is the programKeys of one decision at revision: the caller's
// own program's file identity is read at most once, and every stored
// program's comes from the policy's storedKeys.
func (p *DecisionPolicy) decisionKeys(revision, caller string) programKeys {
	var callerKey string
	callerRead := false
	return func(program string) string {
		if program == caller {
			if !callerRead {
				callerKey, callerRead = identity.ProgramKey(caller), true
			}
			return callerKey
		}
		return p.stored.key(revision, program)
	}
}

// prevails reports whether rule a decides a target over rule b on the same
// target: a deny over a permit, and of two alike the later edit.
func prevails(a, b decisionRule) bool {
	if a.Permit != b.Permit {
		return !a.Permit
	}
	return a.SetAt > b.SetAt
}

// decidingRule is the rule that decides the target at now among the rules on
// it, which spellings that compare equal can make more than one: a rule in
// force before an expired one, then as prevails orders them. False when no
// rule names the target.
func decidingRule(rules []decisionRule, s wire.Subject, action, resource string, now time.Time, key programKeys) (decisionRule, bool) {
	var best decisionRule
	found := false
	for _, r := range rules {
		if !sameTarget(r, s, action, resource, key) {
			continue
		}
		if !found {
			best, found = r, true
			continue
		}
		rLive, bestLive := !expired(r, now), !expired(best, now)
		if rLive != bestLive {
			if rLive {
				best = r
			}
			continue
		}
		if prevails(r, best) {
			best = r
		}
	}
	return best, found
}

// mergeRules keeps one rule per target, sorted by key. Of two rules on one
// target (sameTarget) a deny wins over a permit; of two alike, the later
// edit stays.
func mergeRules(rules []decisionRule) []decisionRule {
	buckets := map[string][]int{}
	key := keyOnce()
	var out []decisionRule
	for _, r := range rules {
		bucket := r.Subject.Account + "\x00" + r.Action + "\x00" + r.Resource
		merged := false
		for _, i := range buckets[bucket] {
			if sameTarget(out[i], r.Subject, r.Action, r.Resource, key) {
				if prevails(r, out[i]) {
					out[i] = r
				}
				merged = true
				break
			}
		}
		if !merged {
			buckets[bucket] = append(buckets[bucket], len(out))
			out = append(out, r)
		}
	}
	slices.SortFunc(out, func(a, b decisionRule) int { return strings.Compare(ruleKey(a), ruleKey(b)) })
	return out
}
func ValidDecisionQuery(action, resource string) bool {
	return boundedDecisionString(action, 128) && boundedDecisionString(resource, 1024)
}

// ValidActionName reports whether action is a registrable <owner>/<name>.
func ValidActionName(action string) bool {
	owner, name, ok := strings.Cut(action, "/")
	return ok && actionPart(owner, 64) && actionPart(name, 63)
}
func actionPart(s string, max int) bool {
	if len(s) == 0 || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || i > 0 && (c == '.' || c == '_' || c == '-') {
			continue
		}
		return false
	}
	return true
}
func validStamp(s string) bool {
	t, e := time.Parse(StampFormat, s)
	return e == nil && t.UTC().Format(StampFormat) == s
}
func stamp(t time.Time) string { return t.UTC().Format(StampFormat) }

// LoadDecisionPolicy configures the seed catalogue and validates the file. The
// seed may be any bounded exact strings; registered actions use <owner>/<name>.
// A file whose rules name an action outside seed and registrations refuses.
// A readable file is brought to canonical spellings once (canonicalizeState).
func LoadDecisionPolicy(path string, seed []string) (*DecisionPolicy, error) {
	return LoadDecisionPolicyWithDefinitions(path, seed, nil)
}
func LoadDecisionPolicyWithDefinitions(path string, seed []string, definitions *DefinitionCatalog) (*DecisionPolicy, error) {
	if len(seed) == 0 || len(seed) > MaxDecisionActions {
		return nil, errors.New("rights: seed catalogue needs 1..64 actions")
	}
	seed = slices.Clone(seed)
	slices.Sort(seed)
	for i, a := range seed {
		if !boundedDecisionString(a, 128) || (i > 0 && seed[i-1] == a) {
			return nil, errors.New("rights: invalid/duplicate catalogue action")
		}
	}
	native, e := serviceSubject()
	if e != nil {
		return nil, e
	}
	p := &DecisionPolicy{path: path, seed: seed, native: native, Definitions: definitions}
	if _, _, e = p.readDecision(); e != nil {
		return p, e
	}
	return p, p.canonicalizeState()
}
func serviceSubject() (wire.Subject, error) {
	u, e := user.Current()
	if e != nil {
		return wire.Subject{}, e
	}
	exe, e := os.Executable()
	if e != nil {
		return wire.Subject{}, e
	}
	return NormalizeDecisionSubject(wire.Subject{Account: u.Uid, Program: exe})
}
func (p *DecisionPolicy) now() time.Time {
	if p.Clock != nil {
		return p.Clock().UTC()
	}
	return time.Now().UTC()
}
func (p *DecisionPolicy) regular() error {
	info, e := os.Lstat(p.path)
	if errors.Is(e, os.ErrNotExist) {
		if p.StateRequired {
			return ErrDecisionStateMissing
		}
		return nil
	}
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() {
		return errors.New("rights: decision state must be regular")
	}
	return nil
}
func ruleKey(r decisionRule) string {
	return r.Subject.Account + "\x00" + r.Subject.Program + "\x00" + r.Action + "\x00" + r.Resource
}
func (p *DecisionPolicy) catalogue(f decisionFile) []string {
	all := slices.Clone(p.seed)
	for _, a := range f.Actions {
		if !slices.Contains(all, a.Action) {
			all = append(all, a.Action)
		}
	}
	slices.Sort(all)
	return all
}
func expired(r decisionRule, now time.Time) bool {
	if r.Expires == "" {
		return false
	}
	t, e := time.Parse(StampFormat, r.Expires)
	return e != nil || !now.Before(t)
}
func (p *DecisionPolicy) decodeDecision(data []byte) (decisionFile, error) {
	var f decisionFile
	if data == nil {
		return decisionFile{Profile: DecisionProfile}, nil
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if e := d.Decode(&f); e != nil {
		return f, e
	}
	if e := d.Decode(new(any)); e != io.EOF {
		return f, errors.New("rights: trailing state")
	}
	version := profileVersion(f.Profile)
	if version < 2 || len(f.Rules) > MaxDecisionRules || len(f.Actions) > MaxDecisionActions || len(f.AppliedOperatorAnswers) > MaxAppliedOperatorAnswers || (version < 4 && len(f.AppliedOperatorAnswers) != 0) || len(f.Descriptions) > MaxDecisionActions || (version < 5 && len(f.Descriptions) != 0) || (version < 7 && len(f.DefaultSwitches) != 0) {
		return f, errors.New("rights: incompatible decision state")
	}
	if e := validDefaultSwitches(f.DefaultSwitches); e != nil {
		return f, e
	}
	for i, id := range f.AppliedOperatorAnswers {
		if !validAnswerID(id) || i > 0 && f.AppliedOperatorAnswers[i-1] >= id {
			return f, errors.New("rights: invalid/duplicate applied operator answer")
		}
	}
	for i, a := range f.Actions {
		if !validStoredSubject(a.By) || !ValidActionName(a.Action) || !validStamp(a.At) || (i > 0 && f.Actions[i-1].Action >= a.Action) {
			return f, errors.New("rights: invalid/duplicate registered action")
		}
	}
	catalogue := p.catalogue(f)
	if len(catalogue) > MaxDecisionActions {
		return f, errors.New("rights: catalogue exceeds its bound")
	}
	for i, d := range f.Descriptions {
		if !validStoredDescription(d.Description) || !validStoredSubject(d.By) || !validStamp(d.At) || !slices.Contains(catalogue, d.Description.Action) || (i > 0 && f.Descriptions[i-1].Description.Action >= d.Description.Action) {
			return f, errors.New("rights: invalid/duplicate action description")
		}
	}
	last := ""
	for _, r := range f.Rules {
		key := ruleKey(r)
		if !validStoredSubject(r.Subject) || !validStoredSubject(r.SetBy) || !ValidDecisionQuery(r.Action, r.Resource) ||
			!slices.Contains(catalogue, r.Action) || key <= last || !validStamp(r.SetAt) || !validWhy(r.Why) ||
			(r.Expires != "" && !validStamp(r.Expires)) ||
			(r.QuestionID != "" && (!boundedDecisionString(r.QuestionID, 128) || !r.Permit || IsMetaRule(r.Action, r.Resource) || f.Profile == previousDecisionProfile)) {
			return f, errors.New("rights: invalid/duplicate rule")
		}
		last = key
	}
	canonical, e := json.Marshal(f)
	if e != nil || !bytes.Equal(data, canonical) {
		return f, errors.New("rights: noncanonical decision state")
	}
	if e := p.validateSelectorState(f); e != nil {
		return f, e
	}
	canonicalizeStored(&f, false)
	return f, nil
}

// canonicalizeState rewrites the state file, under its lock, with every stored
// subject in its canonical spelling, once when the policy loads: a file
// created since a rule was written then reads under the spelling queries use.
// A file already canonical is left as it is.
func (p *DecisionPolicy) canonicalizeState() error {
	return p.change(func(data []byte) ([]byte, error) {
		if data == nil {
			return nil, nil
		}
		f, e := p.decodeDecision(data)
		if e != nil {
			return nil, e
		}
		canonicalizeStored(&f, true)
		before, e := json.Marshal(f)
		if e != nil {
			return nil, e
		}
		if bytes.Equal(before, data) {
			return data, nil
		}
		f.Profile = DecisionProfile
		next, e := json.Marshal(f)
		if e != nil || bytes.Equal(next, data) {
			return data, e
		}
		return next, nil
	})
}

// DecisionReadBudget bounds one read of the decision state. A readable file
// reads in milliseconds. The file store retries a denied open, because a
// writer's replace denies it for an instant, and a file denied for good ends
// that retry at this budget: the decision, rule read or listing is unavailable.
const DecisionReadBudget = 500 * time.Millisecond

func (p *DecisionPolicy) readDecision() (decisionFile, string, error) {
	return p.readDecisionContext(context.Background())
}

// CheckState reads the decision state within ctx and DecisionReadBudget and
// returns why it cannot decide: a missing file under StateRequired, an
// unreadable, oversize or malformed file. Nil means decisions read the file.
// A host reports its decision point not ready while this fails.
func (p *DecisionPolicy) CheckState(ctx context.Context) error {
	_, _, e := p.readDecisionContext(ctx)
	return e
}

// readDecisionContext reads the state within ctx and DecisionReadBudget.
func (p *DecisionPolicy) readDecisionContext(ctx context.Context) (decisionFile, string, error) {
	if e := p.regular(); e != nil {
		return decisionFile{}, "", e
	}
	ctx, cancel := context.WithTimeout(ctx, DecisionReadBudget)
	defer cancel()
	data, e := cas.ReadLimitContext(ctx, p.path, MaxDecisionBytes)
	if e != nil {
		return decisionFile{}, "", e
	}
	definitionDigest := p.Definitions.DefinitionDigest()
	if f, revision, ok := p.decoded.get(data, definitionDigest); ok {
		return f, revision, nil
	}
	f, e := p.decodeDecision(data)
	if e != nil {
		return f, "", e
	}
	revision := p.revision(f)
	p.decoded.put(data, f, revision, definitionDigest)
	return f, revision, nil
}

// decodedState is the last decision state a read decoded, reused for the same
// bytes for at most StoredKeyReuse: decoding validates every rule and
// resolves stored spellings shaped like a short alias, which a read of
// unchanged bytes under the same immutable definition digest need not repeat
// more often than a stored program's file identity is read again. Catalogue
// replacement before Serve changes validation and the effective revision.
// Readers never change a decoded state.
type decodedState struct {
	mu               sync.Mutex
	data             []byte
	f                decisionFile
	revision         string
	definitionDigest string
	read             time.Time
}

func (c *decodedState) get(data []byte, definitionDigest string) (decisionFile, string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if data == nil || c.data == nil || c.definitionDigest != definitionDigest || time.Since(c.read) >= StoredKeyReuse || !bytes.Equal(c.data, data) {
		return decisionFile{}, "", false
	}
	return c.f, c.revision, true
}

// reset forgets the last decoded state, so the next read computes its revision
// under the current configuration.
func (c *decodedState) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = nil
}

func (c *decodedState) put(data []byte, f decisionFile, revision, definitionDigest string) {
	if data == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data, c.f, c.revision, c.definitionDigest, c.read = data, f, revision, definitionDigest, time.Now()
}

// decisionChangeAttempts bounds how often one edit runs again after the file
// store found the state file changed under its lock.
const decisionChangeAttempts = 4

// change runs edit as one locked change of the state file. The file store
// answers cas.ErrMoved when the file changed between its read and its write
// under the lock, which only a writer outside the lock or a removal causes.
// The edit then runs again on the file as it is now, so an unconditional edit
// still lands and a conditional one compares its revision against the new
// content. Each edit sets its whole result on every run.
func (p *DecisionPolicy) change(edit func([]byte) ([]byte, error)) error {
	edit = p.checkedChange(edit)
	var err error
	for attempt := 0; attempt < decisionChangeAttempts; attempt++ {
		if err = cas.ChangeLimit(p.path, MaxDecisionBytes, edit); !errors.Is(err, cas.ErrMoved) {
			return p.committed(err)
		}
	}
	return err
}

// changeContext bounds the new Book-pinned first-use effect's lock wait. It
// preserves the existing retry of a noncooperating writer's compare race.
func (p *DecisionPolicy) changeContext(ctx context.Context, edit func([]byte) ([]byte, error)) error {
	edit = p.checkedChange(edit)
	var err error
	for attempt := 0; attempt < decisionChangeAttempts; attempt++ {
		if err = cas.ChangeLimitContext(ctx, p.path, MaxDecisionBytes, edit); !errors.Is(err, cas.ErrMoved) {
			return p.committed(err)
		}
	}
	return err
}

// Every writer validates the complete resulting state before the shared CAS
// commits. Legacy writers also preserve the combined typed/legacy limits.
func (p *DecisionPolicy) checkedChange(edit func([]byte) ([]byte, error)) func([]byte) ([]byte, error) {
	return func(data []byte) ([]byte, error) {
		next, err := edit(data)
		if err != nil || next == nil {
			return next, err
		}
		if len(next) > MaxDecisionBytes {
			return nil, errors.New("rights: state byte bound")
		}
		if _, err := p.decodeDecision(next); err != nil {
			return nil, err
		}
		return next, nil
	}
}

// ruleChange is one edit of an exact rule. A nil permit revokes. exact compares
// reason and expiry as well as permit when deciding whether the edit is a no-op.
type ruleChange struct {
	permit     *bool
	by         wire.Subject
	at         time.Time
	ttl        time.Duration
	why        string
	exact      bool
	missing    error
	questionID string
}

func (p *DecisionPolicy) editDecision(subject wire.Subject, action, resource string, permit *bool) error {
	// A revoke names the stored rule as it is; only a written rule must have a
	// spelling that can still match once its file appears.
	normalize := NormalizeDecisionSubject
	if permit != nil {
		normalize = writableSubject
	}
	s, e := normalize(subject)
	if errors.Is(e, ErrUnresolvedShortName) {
		return e
	}
	if e != nil || !ValidDecisionQuery(action, resource) {
		return errors.New("rights: invalid exact rule")
	}
	if e = p.refuseHolder(s, action, resource, permit); e != nil {
		return e
	}
	if e = p.regular(); e != nil {
		return e
	}
	change := ruleChange{permit: permit, by: p.native, at: p.now()}
	return p.change(func(data []byte) ([]byte, error) {
		f, e := p.decodeDecision(data)
		if e != nil {
			return nil, e
		}
		if !slices.Contains(p.catalogue(f), action) {
			return nil, ErrUnknownRight
		}
		changed, e := applyDecisionRule(&f, s, action, resource, change)
		if e != nil {
			return nil, e
		}
		if !changed {
			return data, nil
		}
		f.Profile = DecisionProfile
		return json.Marshal(f)
	})
}
func (p *DecisionPolicy) Set(subject wire.Subject, action, resource string, permit bool) error {
	return p.editDecision(subject, action, resource, &permit)
}
func (p *DecisionPolicy) Revoke(subject wire.Subject, action, resource string) error {
	return p.editDecision(subject, action, resource, nil)
}

// RegisterAction adds a <owner>/<name> action to the catalogue with the service's
// own subject as registrant. An action already in the catalogue writes nothing.
func (p *DecisionPolicy) RegisterAction(action string) error {
	if !ValidActionName(action) {
		return errors.New("rights: invalid action name")
	}
	if e := p.regular(); e != nil {
		return e
	}
	at := stamp(p.now())
	return p.change(func(data []byte) ([]byte, error) {
		f, e := p.decodeDecision(data)
		if e != nil {
			return nil, e
		}
		if slices.Contains(p.catalogue(f), action) {
			return data, nil
		}
		if len(p.catalogue(f)) >= MaxDecisionActions {
			return nil, ErrCatalogueFull
		}
		addAction(&f, registeredAction{Action: action, By: p.native, At: at})
		f.Profile = DecisionProfile
		return json.Marshal(f)
	})
}

// Catalogue returns the current seed plus registered actions, sorted.
func (p *DecisionPolicy) Catalogue() ([]string, error) {
	f, _, e := p.readDecision()
	if e != nil {
		return nil, e
	}
	return p.catalogue(f), nil
}
func addAction(f *decisionFile, entry registeredAction) {
	f.Actions = append(f.Actions, entry)
	slices.SortFunc(f.Actions, func(a, b registeredAction) int { return strings.Compare(a.Action, b.Action) })
}
func (p *DecisionPolicy) Decide(subject wire.Subject, action, resource string) wire.Decision {
	return p.DecideContext(context.Background(), subject, action, resource)
}

// DecideContext is Decide with its state read bounded by ctx as well as
// DecisionReadBudget. A read that does not finish in time is unavailable.
func (p *DecisionPolicy) DecideContext(ctx context.Context, subject wire.Subject, action, resource string) wire.Decision {
	return p.CheckLegacyOperationContext(ctx, subject, wire.LegacyOperationRequest{LegacyAction: action, LegacyResource: resource})
}

// pruneExpired removes every rule at or past its expiry.
func pruneExpired(f *decisionFile, now time.Time) {
	f.Rules = slices.DeleteFunc(f.Rules, func(r decisionRule) bool { return expired(r, now) })
	if len(f.Rules) == 0 {
		f.Rules = nil
	}
	pruneSelectorState(f, now)
}

// applyDecisionRule edits the rule on the target (s, action, resource). Every
// stored rule on that target (sameTarget) is the one rule an edit replaces or
// a revoke removes; a written rule takes the edit's own spelling.
func applyDecisionRule(f *decisionFile, s wire.Subject, action, resource string, change ruleChange) (bool, error) {
	key := ruleKey(decisionRule{Subject: s, Action: action, Resource: resource})
	programs := keyOnce()
	var matches []int
	for i, r := range f.Rules {
		if sameTarget(r, s, action, resource, programs) {
			matches = append(matches, i)
		}
	}
	others := func() []decisionRule {
		return slices.DeleteFunc(slices.Clone(f.Rules), func(r decisionRule) bool { return sameTarget(r, s, action, resource, programs) })
	}
	// A class-scoped meta-rule carries the permits its holder wrote
	// (RIGHTS-R16): its end removes them, and a new expiry moves them.
	var oldMeta *decisionRule
	if IsMetaRule(action, resource) {
		if err := validMetaEdit(action, resource, change.permit, change.ttl); err != nil {
			return false, err
		}
		if r, found := liveMeta(f.Rules, s, change.at, programs); found {
			oldMeta = &r
		}
	}
	if change.permit == nil {
		if len(matches) == 0 {
			return false, change.missing
		}
		f.Rules = others()
		if oldMeta != nil {
			cascadeMeta(f, *oldMeta, nil, programs)
		}
		pruneExpired(f, change.at)
		return true, nil
	}
	r := decisionRule{Subject: s, Action: action, Resource: resource, Permit: *change.permit, SetBy: change.by, SetAt: stamp(change.at), Why: change.why, QuestionID: change.questionID}
	if change.ttl > 0 {
		r.Expires = stamp(change.at.Add(change.ttl))
	}
	if len(matches) == 1 {
		old := f.Rules[matches[0]]
		same := old.Permit == r.Permit && !expired(old, change.at)
		if change.exact {
			same = same && old.Why == r.Why && old.Expires == r.Expires
		}
		if same {
			return false, nil
		}
		f.Rules[matches[0]] = r
	} else {
		f.Rules = others()
		pruneExpired(f, change.at)
		if len(f.Rules)+len(f.SelectorRules) >= MaxDecisionRules {
			return false, errors.New("rights: rule capacity reached")
		}
		f.Rules = append(f.Rules, r)
	}
	if oldMeta != nil {
		cascadeMeta(f, *oldMeta, &r, programs)
	}
	pruneKeep(f, key, change.at)
	slices.SortFunc(f.Rules, func(a, b decisionRule) int { return strings.Compare(ruleKey(a), ruleKey(b)) })
	return true, nil
}

// pruneKeep removes expired rules other than the rule just written.
func pruneKeep(f *decisionFile, key string, now time.Time) {
	f.Rules = slices.DeleteFunc(f.Rules, func(r decisionRule) bool { return ruleKey(r) != key && expired(r, now) })
	pruneSelectorState(f, now)
}
