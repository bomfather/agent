package integration

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bomfather/bomfather/agent/integration/testdata/command"
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
	h := buildTestBinary(t)

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
	h := buildTestBinary(t)

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
	h := buildTestBinary(t)

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
	h := buildTestBinary(t)

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
func bootstrapPolicyGlobalReadOnly(t *testing.T, readOnlyPaths ...string) string {
	t.Helper()
	if len(readOnlyPaths) == 0 {
		t.Fatal("bootstrapPolicyGlobalReadOnly: need at least one path")
	}

	var b strings.Builder
	b.WriteString("\nattributes:\n")
	for _, p := range readOnlyPaths {
		fmt.Fprintf(&b, "  - path: \"type = filepath | filepath = %s\"\n    global_read_only: true\n", p)
	}
	return b.String()
}

func TestGlobalReadOnly(t *testing.T) {
	//This tests both the directory and the executable which are both global read-only.
	if os.Getuid() != 0 {
		t.Skip("test must be run as root")
	}
	h := buildTestBinary(t)
	dir := t.TempDir()

	readOnlyTxt := filepath.Join(dir, "read-only.txt")
	if err := os.WriteFile(readOnlyTxt, []byte("original\n"), 0o644); err != nil {
		t.Fatalf("write read-only file: %v", err)
	}

	dummyExec := filepath.Join(dir, "dummy-exec")
	if err := os.WriteFile(dummyExec, []byte("#!/bin/sh\necho ok\n"), 0o755); err != nil {
		t.Fatalf("write dummy exec: %v", err)
	}

	policy := bootstrapPolicyGlobalReadOnly(t, readOnlyTxt, dummyExec)
	runAgent(t, policy)

	for _, path := range []string{readOnlyTxt, dummyExec} {
		cmd := exec.Command(h, command.WriteToReadonly, "0", path)
		if err := cmd.Run(); err != nil {
			t.Fatalf("write to %s should be blocked: %v", path, err)
		}
	}
}

func TestChildCannotReadDirParentWasNotGranted(t *testing.T) {
	// There is one executable: h. It launches itself as a child.
	// h can read the allowed directory.
	// blockedDir is guarded via /bin/true but never granted to h.
	// The child must not read blockedDir.
	if os.Getuid() != 0 {
		t.Skip("test must be run as root")
	}
	h := buildTestBinary(t)

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

	cmd := exec.Command(h, command.ParentReadAllowedChildReadDenied, "2000", allowedFile, blockedFile, h)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatalf("start negative-inheritance helper: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	// h is granted allowedDir; blockedDir is guarded via a dummy owner but not
	// granted to h, so neither h nor its child may read it.
	runAgent(t, bootstrapPolicyReadAllowedAndRegisterSiblingDir(t, h, allowedDir, blockedDir, h))
	err := cmd.Wait()
	if err == nil {
		return
	}

	code := err.(*exec.ExitError).ExitCode()
	switch code {
	case 10:
		t.Fatalf("parent should read its allowed file")
	case 11:
		t.Fatalf("child read the blocked file; it must not exceed the parent's grants")
	default:
		t.Fatalf("unexpected error: %v\n%s", err, output.String())
	}
}
