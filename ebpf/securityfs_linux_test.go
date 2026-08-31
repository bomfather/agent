//go:build linux

package ebpf

import (
	"errors"
	"os"
	"testing"
)

func TestEnsureSecurityfsTreatsBusyAsSuccess(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to mount securityfs")
	}

	if err := ensureSecurityfs(); err != nil {
		t.Fatalf("ensureSecurityfs() = %v", err)
	}
	if err := ensureSecurityfs(); err != nil {
		t.Fatalf("ensureSecurityfs() second call = %v", err)
	}

	if _, err := os.Stat(LSM_LIST_PATH); err != nil {
		t.Fatalf("lsm list missing after ensureSecurityfs(): %v", err)
	}
}

func TestReadLSMListDoesNotUseErrLSMNotEnabledOnReadFailure(t *testing.T) {
	if _, err := os.Stat(LSM_LIST_PATH); err == nil {
		t.Skip("securityfs already provides the lsm list")
	}

	if os.Geteuid() == 0 {
		t.Skip("root can mount securityfs; this case is the unreadable path")
	}

	_, err := readLSMList()
	if err == nil {
		t.Fatal("readLSMList() succeeded unexpectedly")
	}
	if errors.Is(err, ErrLSMNotEnabled) {
		t.Fatalf("read failure wrapped as ErrLSMNotEnabled: %v", err)
	}
}
