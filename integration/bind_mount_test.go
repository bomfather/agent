package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestBindMountTrojan(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test must be run as root")
	}
	configYAML := `
policies:
  - executable: "filepath = {{TEMP_DIR}}/trusted-exec"
    can_access_dirs:
      - "{{TEMP_DIR}}/trusted-exec: read"`
	tempDir := t.TempDir()
	trustedExec := filepath.Join(tempDir, "trusted-exec")
	trojanExec := filepath.Join(tempDir, "trojan-exec")
	if err := os.WriteFile(trustedExec, []byte("#!/bin/sh\necho 'trusted exec'\n"), 0755); err != nil {
		t.Fatalf("create trusted exec: %v", err)
	}
	if err := os.WriteFile(trojanExec, []byte("#!/bin/sh\necho 'trojan exec'\n"), 0755); err != nil {
		t.Fatalf("create trojan exec: %v", err)
	}
	agent := runAgentInDir(t, tempDir, configYAML)
	blocked, err := attemptBindMount(trojanExec, trustedExec)
	if err != nil {
		t.Fatalf("attempt bind mount: %v", err)
	}
	if !blocked {
		unmountBind(t, trustedExec)
		t.Fatalf("bind mount not blocked")
	}

	// tests that are not part of the policy to ensure it is not getting blocked
	nonSecuredDir := filepath.Join(tempDir, "non-secured-dir")
	nonSecuredFile := filepath.Join(nonSecuredDir, "non-secured-file")
	if err := os.MkdirAll(nonSecuredDir, 0755); err != nil {
		t.Fatalf("create non-secured dir: %v", err)
	}
	if err := os.WriteFile(nonSecuredFile, []byte("non-secured file"), 0755); err != nil {
		t.Fatalf("create non-secured file: %v", err)
	}
	blocked, err = attemptBindMount(trojanExec, nonSecuredFile)
	if err != nil {
		t.Fatalf("attempt bind mount: %v", err)
	}
	if blocked {
		t.Fatalf("bind mount blocked")
	}
	unmountBind(t, nonSecuredFile)
	// This is to ensure that the agent is not being overwritten by the trojan exec.
	blocked, err = attemptBindMount(trojanExec, agent.Cmd.Path)
	if err != nil {
		t.Fatalf("attempt bind mount: %v", err)
	}
	if !blocked {
		unmountBind(t, agent.Cmd.Path)
		t.Fatalf("agent executable overwritten should be blocked")
	}
}

func unmountBind(t *testing.T, target string) {
	t.Helper()
	if err := unix.Unmount(target, unix.MNT_DETACH); err != nil {
		t.Errorf("unmount %s: %v", target, err)
	}
}

func attemptBindMount(source, target string) (blocked bool, unsupported error) {
	err := unix.Mount(source, target, "", unix.MS_BIND, "")
	if err == nil {
		return false, nil
	}

	if err == unix.EPERM || err == unix.EACCES {
		return true, nil
	}

	if err == unix.ENOSYS || err == unix.EINVAL || err == unix.ENOTSUP {
		return false, fmt.Errorf("mount unsupported: %w", err)
	}

	return false, err
}
