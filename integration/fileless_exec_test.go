package integration

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/bomfather/bomfather/agent/integration/testdata/command"
)

// blockInMemoryPolicyPrefix enables the fileless execution control and grants
// the helper read on a directory plus permission to run itself. The block is a
// global toggle, so block_in_memory_exec must be set for the fileless checks to
// fire.
const blockInMemoryPolicyPrefix = `
flags:
  block_in_memory_exec: true
policies:
  - executable: "filepath = %s"
    can_access_dirs:
      - "%s: read"
    can_run:
      - "%s"
`

// TestFilelessExecBlocked proves the anti-malware core: a binary run from disk
// is allowed (default-open), but the same bytes executed from an anonymous
// in-memory file (memfd) are blocked. memfd images are exposed to the kernel as
// "memfd:...", which the agent treats as fileless execution.
func TestFilelessExecBlocked(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test must be run as root")
	}
	h := buildTestBinary(t)

	dir := t.TempDir()
	file := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(file, []byte("x\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	// Pre-agent control: confirm this host can execute a memfd image. FilelessRan
	// exits 12 when the in-memory image actually ran. If that does not happen,
	// a later denial would be the host's doing, not the agent's, so skip.
	if err := exec.Command(h, command.FilelessExec).Run(); err == nil {
		t.Skip("memfd execution is not possible on this host, cannot attribute denial to the agent")
	} else if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 12 {
		t.Skipf("memfd execution is not possible on this host, cannot attribute denial to the agent: %v", err)
	}

	policy := fmt.Sprintf(blockInMemoryPolicyPrefix, h, dir, h)
	runAgent(t, policy)

	// Positive control: the same bytes run from disk are allowed, proving the
	// block below is specific to the fileless vector, not the binary itself.
	if err := exec.Command(h, command.Read, file).Run(); err != nil {
		t.Fatalf("disk execution of helper should be allowed: %v", err)
	}

	// Property: fileless (memfd) execution of the same bytes is blocked.
	cmd := exec.Command(h, command.FilelessExec)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	if err == nil {
		return // exit 0 = exec was blocked, helper returned from syscall.Exec
	}

	code := err.(*exec.ExitError).ExitCode()
	switch code {
	case 12:
		t.Fatalf("in-memory (memfd) image executed but should be blocked\n%s", output.String())
	default:
		t.Fatalf("unexpected error from fileless helper: %v\n%s", err, output.String())
	}
}

// TestDevShmExecBlocked proves the /dev/shm fileless vector is blocked: a binary
// copied into /dev/shm and executed is treated as fileless. To disambiguate the
// agent's denial from a noexec mount, the test skips when /dev/shm cannot
// execute a control binary before the agent is running.
func TestDevShmExecBlocked(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test must be run as root")
	}
	h := buildTestBinary(t)

	dir := t.TempDir()
	file := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(file, []byte("x\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	shmExec := copyToDevShm(t, h)

	// Pre-agent control: confirm /dev/shm is exec-capable on this host. If the
	// mount is noexec, a later denial would be the mount's doing, not the agent's,
	// so skip rather than report a false positive.
	if err := exec.Command(shmExec, command.Read, file).Run(); err != nil {
		t.Skipf("/dev/shm is not exec-capable on this host, cannot attribute denial to the agent: %v", err)
	}

	policy := fmt.Sprintf(blockInMemoryPolicyPrefix, h, dir, h)
	runAgent(t, policy)

	// Positive control: the disk copy still runs under the agent.
	if err := exec.Command(h, command.Read, file).Run(); err != nil {
		t.Fatalf("disk execution of helper should be allowed: %v", err)
	}

	// Property: executing the /dev/shm copy is blocked.
	cmd := exec.Command(shmExec, command.Read, file)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err == nil {
		t.Fatalf("execution from /dev/shm should be blocked as fileless\n%s", output.String())
	}
}

// copyToDevShm copies src into a uniquely named executable in /dev/shm and
// registers cleanup.
func copyToDevShm(t *testing.T, src string) string {
	t.Helper()

	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read source binary: %v", err)
	}

	f, err := os.CreateTemp("/dev/shm", "bomfather-fileless-*")
	if err != nil {
		t.Fatalf("create /dev/shm file: %v", err)
	}
	dst := f.Name()
	t.Cleanup(func() { _ = os.Remove(dst) })

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		t.Fatalf("write /dev/shm file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close /dev/shm file: %v", err)
	}
	if err := os.Chmod(dst, 0o755); err != nil {
		t.Fatalf("chmod /dev/shm file: %v", err)
	}
	return dst
}
