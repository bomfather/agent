package integration

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/bomfather/bomfather/agent/integration/testdata/bootstrap_helper/command"
)

const policyPrefix = `
policies:
  - executable: "filepath = %s"
    can_access_dirs:
      - "%s: read"
    can_run:
      - "%s"
`

// bootstrapPolicyReadAllowedAndRegisterSiblingDir returns YAML that lets
// trustedExe read allowedDir and run canRun, and that denies it siblingDir.
//
// siblingDir is listed only on a dummy `true` policy (never executed). That is
// required because a directory that appears in no policy is unrestricted, so
// omitting it from trustedExe would not produce a denial.
func bootstrapPolicyReadAllowedAndRegisterSiblingDir(t *testing.T, trustedExe, allowedDir, siblingDir, canRun string) string {
	t.Helper()
	dummy := mustResolveExecutable(t, "true")
	return fmt.Sprintf(`
policies:
  - executable: "filepath = %s"
    can_access_dirs:
      - "%s: read"
    can_run:
      - "%s"
  - executable: "filepath = %s"
    can_access_dirs:
      - "%s: read"
`, trustedExe, allowedDir, canRun, dummy, siblingDir)
}

// TestProcessStartedBeforeAgentAndChildCanRead starts the helper before the
// agent attaches, then checks that the already-running parent and a child it
// spawns can still read an allowed directory.
func TestProcessStartedBeforeAgentAndChildCanRead(t *testing.T) {
	h := bootstrapHelperExe(t)

	protectedDir := filepath.Join(t.TempDir(), "protected")
	if err := os.MkdirAll(protectedDir, 0o755); err != nil {
		t.Fatalf("create protected directory: %v", err)
	}

	protectedFile := filepath.Join(protectedDir, "pre-agent.txt")
	if err := os.WriteFile(protectedFile, []byte("pre-agent\n"), 0o644); err != nil {
		t.Fatalf("write protected file: %v", err)
	}

	policy := fmt.Sprintf(policyPrefix, h, protectedDir, h)
	cmd := exec.Command(h, command.PreagentParentReadChild, "2000", protectedFile, h)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start process before agent: %v", err)
	}

	time.Sleep(100 * time.Millisecond)
	runAgent(t, policy)
	err := cmd.Wait()
	if err == nil {
		return
	}

	code := err.(*exec.ExitError).ExitCode()
	switch code {
	case 10:
		t.Fatalf("parent should still read after the agent attaches")
	case 11:
		t.Fatalf("child should inherit read access")
	default:
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestProcessStartedAfterAgentAndChildCanRead starts the agent first, then
// checks that a later parent and the child it spawns can read an allowed
// directory via the normal exec path.
func TestProcessStartedAfterAgentAndChildCanRead(t *testing.T) {
	h := bootstrapHelperExe(t)

	preAgentDir := t.TempDir()
	protectedDir := filepath.Join(preAgentDir, "protected")
	if err := os.MkdirAll(protectedDir, 0o755); err != nil {
		t.Fatalf("create protected directory: %v", err)
	}
	policy := fmt.Sprintf(policyPrefix, h, protectedDir, h)

	protectedFile := filepath.Join(protectedDir, "normal-process.txt")
	if err := os.WriteFile(protectedFile, []byte("normal process content\n"), 0o644); err != nil {
		t.Fatalf("write protected file: %v", err)
	}

	runAgent(t, policy)

	cmd := exec.Command(h, command.ParentReadChild, protectedFile, h)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start process after agent: %v", err)
	}
	err := cmd.Wait()
	if err == nil {
		return
	}

	code := err.(*exec.ExitError).ExitCode()
	switch code {
	case 10:
		t.Fatalf("parent should read when started after the agent")
	case 11:
		t.Fatalf("child should inherit read access")
	default:
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBootstrapEnforcesOwnPolicy(t *testing.T) {
	h := bootstrapHelperExe(t)

	preAgentDir := t.TempDir()
	allowedDir := filepath.Join(preAgentDir, "allowed")
	blockedDir := filepath.Join(preAgentDir, "blocked")
	if err := os.MkdirAll(allowedDir, 0o755); err != nil {
		t.Fatalf("create allowed directory: %v", err)
	}
	if err := os.MkdirAll(blockedDir, 0o755); err != nil {
		t.Fatalf("create blocked directory: %v", err)
	}

	allowedFile := filepath.Join(allowedDir, "allowed.txt")
	blockedFile := filepath.Join(blockedDir, "blocked.txt")
	if err := os.WriteFile(allowedFile, []byte("allowed\n"), 0o644); err != nil {
		t.Fatalf("write allowed file: %v", err)
	}
	if err := os.WriteFile(blockedFile, []byte("blocked\n"), 0o644); err != nil {
		t.Fatalf("write blocked file: %v", err)
	}

	cmd := exec.Command(h, command.ReadAndBlocked, "2000", allowedFile, blockedFile)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatalf("start bootstrap policy helper: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	runAgent(t, bootstrapPolicyReadAllowedAndRegisterSiblingDir(t, h, allowedDir, blockedDir, h))
	err := cmd.Wait()
	if err == nil {
		return
	}

	code := err.(*exec.ExitError).ExitCode()
	switch code {
	case 10:
		t.Fatalf("allowed file should be read")
	case 11:
		t.Fatalf("blocking sibling directory should be denied")
	default:
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReadonlyFileWriteBlocked(t *testing.T) {
	h := bootstrapHelperExe(t)

	preAgentDir := t.TempDir()
	protectedDir := filepath.Join(preAgentDir, "protected")
	if err := os.MkdirAll(protectedDir, 0o755); err != nil {
		t.Fatalf("create protected directory: %v", err)
	}

	targetFile := filepath.Join(protectedDir, "readonly-target.txt")
	if err := os.WriteFile(targetFile, []byte("original\n"), 0o644); err != nil {
		t.Fatalf("write target file: %v", err)
	}

	cmd := exec.Command(h, command.WriteToReadonly, "2000", targetFile)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatalf("start bootstrap readonly helper: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	policy := fmt.Sprintf(policyPrefix, h, protectedDir, h)
	runAgent(t, policy)
	err := cmd.Wait()
	if err == nil {
		return
	}

	code := err.(*exec.ExitError).ExitCode()
	switch code {
	case 10:
		t.Fatalf("write to readonly file should be blocked")
	case 11:
		t.Fatalf("should have been able to read the file")
	default:
		t.Fatalf("unexpected error: %v", err)
	}
}
