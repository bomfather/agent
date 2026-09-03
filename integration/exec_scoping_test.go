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

// bootstrapPolicyReadOnlyForExecutable returns a policy that builds a policy where there are two executables
// and two grants.
// The executables are: grantedExe and otherExe.
// The grantedExed has access to sharedDir and otherExe has access to otherDir.
// We have to explicitly include the otherExe in the policy, if not it would be open to everyone.
// Bomfather doesn't make any assumptions and it has to be explicitly opted in.
func bootstrapPolicyReadOnlyForExecutable(t *testing.T, grantedExe, sharedDir, otherExe, otherDir string) string {
	t.Helper()
	return fmt.Sprintf(`
policies:
  # grantedExe: the binary that may read sharedDir (the path under test).
  - executable: "filepath = %s"
    can_access_dirs:
      - "%s: read"  # sharedDir
    can_run:
      - "%s"
  # otherExe: registered with a different directory so this is not an
  # unregistered binary. Does not get sharedDir.
  - executable: "filepath = %s"
    can_access_dirs:
      - "%s: read"  # otherDir; unused by the test
    can_run:
      - "%s"
`, grantedExe, sharedDir, grantedExe, otherExe, otherDir, otherExe)
}

// bootstrapPolicyExecScoped returns a policy where there are two executables
// and two grants.
//
// Example: /bin/app may read its work dir and launch only itself.
// /usr/bin/secret-tool is listed on /bin/true's can_run so it is guarded.
// We do not put /usr/bin/secret-tool on its own can_run list (then anyone could launch it).
// /bin/app trying to exec /usr/bin/secret-tool is denied.
func bootstrapPolicyExecScoped(t *testing.T, runner, runnerDir, forbidden string) string {
	t.Helper()
	return fmt.Sprintf(`
policies:
  # /bin/app (runner): may read its work dir and launch only itself.
  - executable: "filepath = %s"
    can_access_dirs:
      - "%s: read"
    can_run:
      - "%s"
  # /bin/true: the only process allowed to exec /usr/bin/secret-tool.
  # Never started. Listing forbidden here is what guards it.
  - executable: "filepath = /bin/true"
    can_run:
      - "%s"  # /usr/bin/secret-tool
`, runner, runnerDir, runner, forbidden)
}

// buildTestBinaryAt builds a second copy of the test binary at a new path, so a
// test has two distinct binaries to check that permissions are scoped per
// executable.
func buildTestBinaryAt(t *testing.T) string {
	t.Helper()

	integrationDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}

	bin := filepath.Join(t.TempDir(), "test_binary_second")
	srcDir := filepath.Join(integrationDir, "testdata", "test_binary")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = srcDir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build second test binary: %v\n%s", err, out)
	}
	return bin
}

func mustExitCode(t *testing.T, err error) int {
	t.Helper()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("unexpected error: %v", err)
	}
	return exitErr.ExitCode()
}

// TestReadScopedToExecutable checks that a directory grant applies only to the
// executable it was given to. Two helper binaries run: the granted one can read
// the shared file, and the other one, granted a different directory, is denied.
func TestReadScopedToExecutable(t *testing.T) {
	// There are two executables: granted and denied.
	// The granted executable is granted the shared file and can read it.
	// The denied executable can read the other file but cannot read the shared file.
	if os.Getuid() != 0 {
		t.Skip("test must be run as root")
	}
	granted := buildTestBinary(t)
	denied := buildTestBinaryAt(t)

	base := t.TempDir()
	sharedDir := filepath.Join(base, "shared")
	otherDir := filepath.Join(base, "other")
	if err := os.MkdirAll(sharedDir, 0o755); err != nil {
		t.Fatalf("create shared directory: %v", err)
	}
	if err := os.MkdirAll(otherDir, 0o755); err != nil {
		t.Fatalf("create other directory: %v", err)
	}

	sharedFile := filepath.Join(sharedDir, "shared.txt")
	if err := os.WriteFile(sharedFile, []byte("shared\n"), 0o644); err != nil {
		t.Fatalf("write shared file: %v", err)
	}

	policy := bootstrapPolicyReadOnlyForExecutable(t, granted, sharedDir, denied, otherDir)
	runAgent(t, policy)

	// Granted executable must read sharedFile.
	grantedCmd := exec.Command(granted, command.Read, sharedFile)
	var grantedOut bytes.Buffer
	grantedCmd.Stdout = &grantedOut
	grantedCmd.Stderr = &grantedOut
	if err := grantedCmd.Run(); err != nil {
		t.Fatalf("granted executable should read shared file: %v\n%s", err, grantedOut.String())
	}

	// Denied executable must be blocked reading the same file.
	deniedCmd := exec.Command(denied, command.ReadMustBeDenied, sharedFile)
	var deniedOut bytes.Buffer
	deniedCmd.Stdout = &deniedOut
	deniedCmd.Stderr = &deniedOut
	err := deniedCmd.Run()
	if err == nil {
		return // exit 0 = correctly denied
	}

	code := mustExitCode(t, err)
	switch code {
	case 10:
		t.Fatalf("second executable should be denied reading %s but it succeeded", sharedFile)
	default:
		t.Fatalf("unexpected error from denied helper: %v\n%s", err, deniedOut.String())
	}
}

func TestExecScopedByCanRun(t *testing.T) {
	// There are two executables: h and forbidden.
	// h can read the file and launch only itself. It then tries to exec
	// forbidden as a child; that must be denied (exit 11).
	// forbidden is listed on /bin/true's can_run so it is guarded. If no
	// policy mentioned it, anyone could run it.
	if os.Getuid() != 0 {
		t.Skip("test must be run as root")
	}
	h := buildTestBinary(t)
	forbidden := buildTestBinaryAt(t) // a second binary h is not allowed to run

	dir := t.TempDir()
	file := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(file, []byte("x\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	// The policy lets h run only itself, and guards forbidden via a dummy owner.
	policy := bootstrapPolicyExecScoped(t, h, dir, forbidden)
	runAgent(t, policy)

	// h reads the file, then tries to run forbidden as a child. The child launch
	// must be blocked, which the helper reports as exit 11.
	cmd := exec.Command(h, command.ParentReadChild, file, forbidden)
	err := cmd.Run()
	if err == nil {
		t.Fatalf("h should not be allowed to run %s", forbidden)
	}
	if code := mustExitCode(t, err); code != 11 {
		t.Fatalf("expected child-exec denial (exit 11), got %d", code)
	}
}

func TestSelfRunnableExecutableRunnableByAnyone(t *testing.T) {
	// There are two executables: h and target.
	// h can read the file and launch only itself. It was never granted target.
	// target can run itself, which means anyone (including h) can launch it.
	if os.Getuid() != 0 {
		t.Skip("test must be run as root")
	}
	h := buildTestBinary(t)
	target := buildTestBinaryAt(t)

	dir := t.TempDir()
	file := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(file, []byte("x\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	// target is allowed to run itself, which makes it launchable by anyone.
	policy := fmt.Sprintf(`
policies:
  # h: the launcher. Granted its work dir and itself, not target.
  - executable: "filepath = %s"
    can_access_dirs:
      - "%s: read"
    can_run:
      - "%s"
  # target: allowed to run itself, which makes any caller able to launch it.
  - executable: "filepath = %s"
    can_run:
      - "%s"
`, h, dir, h, target, target)
	runAgent(t, policy)

	// h execs target; even though h wasn't granted target, target self-authorizes.
	if err := exec.Command(h, command.ParentReadChild, file, target).Run(); err != nil {
		t.Fatalf("self-runnable target should be launchable by any caller: %v", err)
	}
}

func TestUnregisteredExecutableStillBlockedFromGuardedDir(t *testing.T) {
	// There are two executables: h and newtool.
	// h can read the guarded directory and launch only itself.
	// newtool is unregistered and cannot read the guarded directory.
	if os.Getuid() != 0 {
		t.Skip("test must be run as root")
	}
	h := buildTestBinary(t)
	newtool := buildTestBinaryAt(t) // unregistered

	dir := t.TempDir()
	guarded := filepath.Join(dir, "guarded")
	if err := os.MkdirAll(guarded, 0o755); err != nil {
		t.Fatalf("create guarded dir: %v", err)
	}
	secret := filepath.Join(guarded, "secret.txt")
	if err := os.WriteFile(secret, []byte("secret\n"), 0o644); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	// guarded is registered as a grant to h only. newtool is unregistered.
	policy := fmt.Sprintf(policyPrefix, h, guarded, h)
	runAgent(t, policy)

	// Baseline: h (granted) can read it.
	if err := exec.Command(h, command.Read, secret).Run(); err != nil {
		t.Fatalf("granted h should read guarded file: %v", err)
	}

	// Property: unregistered newtool is denied the guarded dir.
	err := exec.Command(newtool, command.ReadMustBeDenied, secret).Run()
	if err == nil {
		return // exit 0 = correctly denied
	}
	if code := mustExitCode(t, err); code == 10 {
		t.Fatalf("unregistered %s read guarded file but should be denied", newtool)
	} else {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUnregisteredExecutableIsAllowed(t *testing.T) {
	// There are two executables: h and newtool.
	// h can read the file and launch only itself.
	// newtool is unregistered; default-open allows it to run and read the file.
	if os.Getuid() != 0 {
		t.Skip("test must be run as root")
	}
	h := buildTestBinary(t)
	newtool := buildTestBinaryAt(t) // present in NO policy

	dir := t.TempDir()
	file := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(file, []byte("x\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	// Policy names only h. newtool is unregistered -> default-open should allow it.
	policy := fmt.Sprintf(policyPrefix, h, dir, h)
	runAgent(t, policy)

	// h reads file (granted), then execs the unregistered newtool as its child.
	err := exec.Command(h, command.ParentReadChild, file, newtool).Run()
	if err == nil {
		return
	}

	code := mustExitCode(t, err)
	switch code {
	case 10:
		t.Fatalf("granted h should read its allowed file")
	case 11:
		t.Fatalf("unregistered binary %s should be allowed to run (default-open)", newtool)
	default:
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCanRunGrantAllowsLaunch(t *testing.T) {
	// There are two executables: h and tool.
	// h can read the file and launch tool.
	// tool is not allowed to run itself; only h may launch it.
	if os.Getuid() != 0 {
		t.Skip("test must be run as root")
	}
	h := buildTestBinary(t)
	tool := buildTestBinaryAt(t)

	dir := t.TempDir()
	file := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(file, []byte("x\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	policy := fmt.Sprintf(policyPrefix, h, dir, tool)
	runAgent(t, policy)

	if err := exec.Command(h, command.ParentReadChild, file, tool).Run(); err != nil {
		t.Fatalf("h should be allowed to run %s: %v", tool, err)
	}
}

func TestCanRunGrantIsNotSymmetric(t *testing.T) {
	// There are two executables: h and tool.
	// h can read the file and launch tool. tool can read the file and
	// launch only itself.
	// h is listed on /bin/true's can_run so it is guarded. If no policy
	// mentioned it, anyone (including tool) could run it.
	// tool trying to launch h must be denied.
	if os.Getuid() != 0 {
		t.Skip("test must be run as root")
	}
	h := buildTestBinary(t)
	tool := buildTestBinaryAt(t)

	dir := t.TempDir()
	file := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(file, []byte("x\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	policy := fmt.Sprintf(`
policies:
  - executable: "filepath = %s"
    can_access_dirs:
      - "%s: read"
    can_run:
      - "%s"
  - executable: "filepath = %s"
    can_access_dirs:
      - "%s: read"
    can_run:
      - "%s"
  - executable: "filepath = /bin/true"
    can_run:
      - "%s"
`, h, dir, tool, tool, dir, tool, h)
	runAgent(t, policy)

	err := exec.Command(tool, command.ParentReadChild, file, h).Run()
	if err == nil {
		t.Fatalf("tool should not be allowed to run %s", h)
	}
	if code := mustExitCode(t, err); code != 11 {
		t.Fatalf("expected child-exec denial (exit 11), got %d", code)
	}
}

func TestCanRunGrantIsNotTransitive(t *testing.T) {
	// There are three executables: h, mid, and leaf.
	// h can read the file and launch mid.
	// mid can launch leaf.
	// h trying to launch leaf must be denied.
	if os.Getuid() != 0 {
		t.Skip("test must be run as root")
	}
	h := buildTestBinary(t)
	mid := buildTestBinaryAt(t)
	leaf := buildTestBinaryAt(t)

	dir := t.TempDir()
	file := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(file, []byte("x\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	policy := fmt.Sprintf(`
policies:
  - executable: "filepath = %s"
    can_access_dirs:
      - "%s: read"
    can_run:
      - "%s"
  - executable: "filepath = %s"
    can_run:
      - "%s"
`, h, dir, mid, mid, leaf)
	runAgent(t, policy)

	if err := exec.Command(h, command.ParentReadChild, file, mid).Run(); err != nil {
		t.Fatalf("h should be allowed to run %s: %v", mid, err)
	}

	err := exec.Command(h, command.ParentReadChild, file, leaf).Run()
	if err == nil {
		t.Fatalf("h should not be allowed to run %s", leaf)
	}
	if code := mustExitCode(t, err); code != 11 {
		t.Fatalf("expected child-exec denial (exit 11), got %d", code)
	}
}

func TestUnregisteredExecutableCannotLaunchGuardedBinary(t *testing.T) {
	// There are two executables: newtool and forbidden.
	// newtool is unregistered.
	// forbidden is listed on /bin/true's can_run so it is guarded. If no
	// policy mentioned it, anyone could run it.
	// newtool trying to launch forbidden must be denied.
	if os.Getuid() != 0 {
		t.Skip("test must be run as root")
	}
	newtool := buildTestBinaryAt(t)
	forbidden := buildTestBinaryAt(t)

	dir := t.TempDir()
	file := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(file, []byte("x\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	policy := fmt.Sprintf(`
policies:
  - executable: "filepath = /bin/true"
    can_run:
      - "%s"
`, forbidden)
	runAgent(t, policy)

	err := exec.Command(newtool, command.ParentReadChild, file, forbidden).Run()
	if err == nil {
		t.Fatalf("unregistered %s should not be allowed to run %s", newtool, forbidden)
	}
	if code := mustExitCode(t, err); code != 11 {
		t.Fatalf("expected child-exec denial (exit 11), got %d", code)
	}
}

func TestUnregisteredExecutableCanReadUnguardedDir(t *testing.T) {
	// There are two executables: h and newtool.
	// h can read the guarded directory and launch only itself.
	// openDir is not in any policy.
	// newtool is unregistered and can read openDir.
	if os.Getuid() != 0 {
		t.Skip("test must be run as root")
	}
	h := buildTestBinary(t)
	newtool := buildTestBinaryAt(t)

	base := t.TempDir()
	guarded := filepath.Join(base, "guarded")
	openDir := filepath.Join(base, "open")
	if err := os.MkdirAll(guarded, 0o755); err != nil {
		t.Fatalf("create guarded directory: %v", err)
	}
	if err := os.MkdirAll(openDir, 0o755); err != nil {
		t.Fatalf("create open directory: %v", err)
	}
	openFile := filepath.Join(openDir, "open.txt")
	if err := os.WriteFile(openFile, []byte("open\n"), 0o644); err != nil {
		t.Fatalf("write open file: %v", err)
	}

	policy := fmt.Sprintf(policyPrefix, h, guarded, h)
	runAgent(t, policy)

	if err := exec.Command(newtool, command.Read, openFile).Run(); err != nil {
		t.Fatalf("unregistered %s should read unguarded file: %v", newtool, err)
	}
}
