//go:build !windows

package rights

import (
	"os/exec"
	"runtime"
)

func keepAwake(who, why string) (func(), error) {
	var c *exec.Cmd
	if runtime.GOOS == "darwin" {
		c = exec.Command("caffeinate", "-i", "-s")
	} else {
		c = exec.Command("systemd-inhibit", "--what=idle:sleep", "--mode=block",
			"--who="+who, "--why="+why, "sleep", "infinity")
	}
	if err := c.Start(); err != nil {
		return nil, err
	}
	return func() { c.Process.Kill(); c.Wait() }, nil
}
