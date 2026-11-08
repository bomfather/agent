package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/bomfather/bomfather/agent/integration/testdata/command"
)

func mprotectPolicy(helper, dir string, block, allow bool) string {
	flags := ""
	if block {
		flags = "flags:\n  block_in_memory_exec: true\n"
	}
	policy := fmt.Sprintf(`
%s
policies:
  - executable: "filepath = %s"
    can_access_dirs:
      - "%s: read"
    can_run:
      - "%s"
`, flags, helper, dir, helper)
	if allow {
		policy += fmt.Sprintf(`
attributes:
  - path: "type = executable | filepath = %s"
    allowed_in_memory_exec: true
`, helper)
	}
	return policy
}

func TestMprotectExec(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test must be run as root")
	}

	helper := buildTestBinary(t)
	dir := t.TempDir()
	payload := filepath.Join(dir, "payload")
	if err := os.WriteFile(payload, make([]byte, os.Getpagesize()), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	if code := runPtraceHelper(t, helper, command.MprotectNoExec); code != command.ExitAccessible {
		t.Fatalf("mprotect without execute should succeed before the agent, got exit %d", code)
	}
	anonAllowed := runPtraceHelper(t, helper, command.MprotectAnon) == command.ExitAccessible
	fileAllowed := runPtraceHelper(t, helper, command.MprotectFile, payload) == command.ExitAccessible
	if !anonAllowed {
		t.Log("host denies anonymous mprotect exec; that vector cannot be attributed to the agent")
	}
	if !fileAllowed {
		t.Log("host denies file mprotect exec; that vector cannot be attributed to the agent")
	}

	t.Run("block off", func(t *testing.T) {
		runAgent(t, mprotectPolicy(helper, dir, false, false))
		expectMprotect(t, helper, payload, anonAllowed, fileAllowed, command.ExitAccessible)
	})

	t.Run("block on", func(t *testing.T) {
		runAgent(t, mprotectPolicy(helper, dir, true, false))
		if code := runPtraceHelper(t, helper, command.MprotectNoExec); code != command.ExitAccessible {
			t.Fatalf("mprotect without execute should stay allowed, got exit %d", code)
		}
		if anonAllowed {
			if code := runPtraceHelper(t, helper, command.MprotectAnon); code != command.ExitBlocked {
				t.Fatalf("anonymous mprotect exec should be blocked, got exit %d", code)
			}
		}
		if fileAllowed {
			if code := runPtraceHelper(t, helper, command.MprotectFile, payload); code != command.ExitBlocked {
				t.Fatalf("file mprotect exec should be blocked, got exit %d", code)
			}
		}
	})

	t.Run("allowlisted", func(t *testing.T) {
		runAgent(t, mprotectPolicy(helper, dir, true, true))
		expectMprotect(t, helper, payload, anonAllowed, fileAllowed, command.ExitAccessible)
	})
}

func expectMprotect(t *testing.T, helper, payload string, anon, file bool, want int) {
	t.Helper()
	if code := runPtraceHelper(t, helper, command.MprotectNoExec); code != command.ExitAccessible {
		t.Fatalf("mprotect-noexec = %d, want %d", code, command.ExitAccessible)
	}
	if anon {
		if code := runPtraceHelper(t, helper, command.MprotectAnon); code != want {
			t.Fatalf("mprotect-anon = %d, want %d", code, want)
		}
	}
	if file {
		if code := runPtraceHelper(t, helper, command.MprotectFile, payload); code != want {
			t.Fatalf("mprotect-file = %d, want %d", code, want)
		}
	}
}
