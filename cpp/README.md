# C++ rights decisions

`abstraction::rights_client` is supplied by the installed `abstraction_rights`
CMake package. It uses generated Authorization codecs and shared identity IPC.
`rights::Client(endpoint).Decide(action, resource)` asks about the receiving
account/program. Only permitted authorizes an enforcement point to proceed.
Evaluated decisions carry a policy revision; failures carry none. The client
validates this relationship before returning.

`Client(endpoint)` uses a fresh five-second budget per call. The constructor
accepting `ipc::Deadline` retains a caller budget, and `WithCancellation(token)`
retains shared cancellation.

`TrustedEnforcerClient(Client)` exposes `DecideFor(subject, action, resource)`
for receiver-designated enforcement points. The receiver must authorize the
immediate peer for every relayed action/resource. Construction and serialized
Subject fields convey no authority. The enforcer must supply its actual bound
subject. Ordinary applications use Decide. Resource services make their own
policy queries; callers cannot submit a decision as proof of permission.

For resolution use optional `abstraction_facade_rights`, target
`abstraction::facade_rights`, header `abstraction/facade/rights.hpp`.
ResolveTrustedRightsEnforcer makes the trusted relay role explicit. This profile
provides point-in-time decisions; live awake leases and administrative grants
remain separate native integrations. No published release version is claimed.
