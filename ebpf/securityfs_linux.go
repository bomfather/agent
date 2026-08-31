//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

const securityFSPath = "/sys/kernel/security"

func readLSMList() (string, error) {
	b, err := os.ReadFile(LSM_LIST_PATH)
	if errors.Is(err, os.ErrNotExist) {
		if mountErr := ensureSecurityfs(); mountErr != nil {
			return "", fmt.Errorf("mount securityfs on %s: %w", securityFSPath, mountErr)
		}
		b, err = os.ReadFile(LSM_LIST_PATH)
	}
	if err != nil {
		return "", fmt.Errorf("read %s: %w", LSM_LIST_PATH, err)
	}
	return strings.TrimSpace(string(b)), nil
}

func ensureSecurityfs() error {
	err := unix.Mount("securityfs", securityFSPath, "securityfs", 0, "")
	if err != nil && !errors.Is(err, unix.EBUSY) {
		return err
	}
	return nil
}
