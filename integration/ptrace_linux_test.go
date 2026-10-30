package integration

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/bomfather/bomfather/agent/integration/testdata/command"
)

func ptracePolicy(helper, dir string, block, allow bool) string {
	blockLine := ""
	if block {
		blockLine = "  block_ptrace: true\n"
	}
	policy := fmt.Sprintf(`
flags:
  security_level: "sandbox"
%s
policies:
  - executable: "filepath = %s"
    can_access_dirs:
      - "%s: read"
`, blockLine, helper, dir)
	if allow {
		policy += fmt.Sprintf(`
attributes:
  - path: "type = executable | filepath = %s"
    allowed_ptrace: true
`, helper)
	}
	return policy
}

func runPtraceHelper(t *testing.T, helper string, args ...string) int {
	t.Helper()
	cmd := exec.Command(helper, args...)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	t.Logf("%s output:\n%s", args, output.String())
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	t.Fatalf("run %v: %v\n%s", args, err, output.String())
	return -1
}

func TestBlockPtrace(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test must be run as root")
	}

	helper := buildTestBinary(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("x\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	// Confirm this host allows a parent to trace its child before the agent is
	// loaded. Otherwise a later denial cannot be attributed to the agent.
	if code := runPtraceHelper(t, helper, command.PtraceAttach); code != command.ExitAccessible {
		t.Skipf("host does not allow ptrace of a child (exit %d); cannot attribute a denial to the agent", code)
	}

	t.Run("block_ptrace off: attach is allowed", func(t *testing.T) {
		runAgent(t, ptracePolicy(helper, dir, false, false))
		if code := runPtraceHelper(t, helper, command.PtraceAttach); code != command.ExitAccessible {
			t.Fatalf("attach should be allowed when block_ptrace is off, got exit %d", code)
		}
	})

	t.Run("block_ptrace on: attach is blocked", func(t *testing.T) {
		runAgent(t, ptracePolicy(helper, dir, true, false))
		if code := runPtraceHelper(t, helper, command.PtraceAttach); code != command.ExitBlocked {
			t.Fatalf("attach of a protected child should be blocked, got exit %d", code)
		}
	})

	t.Run("block_ptrace on: stat can be read", func(t *testing.T) {
		runAgent(t, ptracePolicy(helper, dir, true, false))
		if code := runPtraceHelper(t, helper, command.PtraceStat); code != command.ExitAccessible {
			t.Fatalf("reading /proc/pid/stat should stay allowed, got exit %d", code)
		}
	})

	t.Run("block_ptrace on: mem is blocked", func(t *testing.T) {
		runAgent(t, ptracePolicy(helper, dir, true, false))
		if code := runPtraceHelper(t, helper, command.PtraceMem); code != command.ExitBlocked {
			t.Fatalf("opening /proc/pid/mem should be blocked, got exit %d", code)
		}
	})

	t.Run("allowlisted tracer: attach is allowed", func(t *testing.T) {
		runAgent(t, ptracePolicy(helper, dir, true, true))
		if code := runPtraceHelper(t, helper, command.PtraceAttach); code != command.ExitAccessible {
			t.Fatalf("allowlisted tracer should attach, got exit %d", code)
		}
	})

	t.Run("block_ptrace on: traceme is blocked", func(t *testing.T) {
		// Run before the agent so a host that already rejects traceme does not look like an agent denial.
		if code := runPtraceHelper(t, helper, command.PtraceTraceme); code != command.ExitAccessible {
			t.Skipf("host does not allow a child to PTRACE_TRACEME (exit %d); cannot attribute a denial to the agent", code)
		}
		runAgent(t, ptracePolicy(helper, dir, true, false))
		if code := runPtraceHelper(t, helper, command.PtraceTraceme); code != command.ExitBlocked {
			t.Fatalf("traceme of a protected child should be blocked, got exit %d", code)
		}
	})
}
