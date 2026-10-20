package rights

import (
	"context"
	"errors"
	"syscall"
	"testing"
	"time"
)

func TestMetaRefreshKeepsActualPolicyReadBounded(t *testing.T) {
	f := newMetaFixture(t)
	f.enroll(t, MetaRuleLapse)
	path, err := syscall.UTF16PtrFromString(f.p.path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := syscall.CreateFile(path, syscall.GENERIC_WRITE, 0, nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(handle)
	start := time.Now()
	err = f.p.CheckState(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) < DecisionReadBudget || time.Since(start) > 1500*time.Millisecond {
		t.Fatal("blocked policy read lost its independent 500ms cap", err, time.Since(start))
	}
}
