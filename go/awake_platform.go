package rights

import platform "github.com/openabstractions/abstraction-resource/go/platform"

// keepAwake retains the legacy server's connection-owned hold through the resource platform owner.
func keepAwake(who, why string) (func(), error) {
	return platform.KeepAwake(who, why, false)
}
