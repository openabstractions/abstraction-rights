package rights

import (
	"context"

	"github.com/openabstractions/abstraction-identity/listen"
)

// Question is a registration this service cannot decide, put to whoever
// answers for the person: Asker is the application's name, Key the question
// ("rights.register"), Slots its words and For the program that connected.
type Question struct {
	Asker string
	Key   string
	Slots map[string]string
	For   *listen.Seen
}

// Decision is the person's answer to a Question. Kept means the answer stands
// for later registrations too, so a refusal is not asked again.
type Decision struct {
	Yes  bool
	Kept bool
}

// Asker puts a Question and waits for the Decision, or for ctx to end.
//
// The asks layer depends on rights, so rights names what it needs here and the
// runtime composition (serve) supplies an Asker backed by the asks client.
// The source repository's import-direction check keeps that direction.
type Asker interface {
	Await(ctx context.Context, q Question) (Decision, error)
}
