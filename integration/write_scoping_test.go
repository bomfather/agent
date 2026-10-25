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

// TestWriteScopedToExecutable checks that a directory write grant applies only
// to the executable it was given to.
func TestWriteScopedToExecutable(t *testing.T) {
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

	policy := fmt.Sprintf(`
policies:
  - executable: "filepath = %s"
    can_access_dirs:
      - "%s: write"
    can_run:
      - "%s"
  - executable: "filepath = %s"
    can_access_dirs:
      - "%s: write"
    can_run:
      - "%s"
`, granted, sharedDir, granted, denied, otherDir, denied)

	runAgent(t, policy)

	// Granted executable must write sharedFile.
	grantedCmd := exec.Command(granted, command.Write, sharedFile)

	var grantedOut bytes.Buffer // we want to read the output
	grantedCmd.Stdout = &grantedOut
	grantedCmd.Stderr = &grantedOut

	if err := grantedCmd.Run(); err != nil {
		t.Fatalf("granted executable should write shared file: %v\n%s", err, grantedOut.String())
	}

	// Denied executable must be blocked writing the same file.
	deniedCmd := exec.Command(denied, command.WriteMustBeDenied, sharedFile)

	var deniedOut bytes.Buffer
	deniedCmd.Stdout = &deniedOut
	deniedCmd.Stderr = &deniedOut

	if err := deniedCmd.Run(); err != nil {
		t.Fatalf("second executable should be denied writing %s: %v\n%s", sharedFile, err, deniedOut.String())
	}
}

// TestTruncateNeedsWriteGrant checks that an executable with only a read grant
// cannot truncate a file, either with an O_RDONLY|O_TRUNC open or truncate(2).
func TestTruncateNeedsWriteGrant(t *testing.T) {
	reader := buildTestBinary(t)

	readDir := filepath.Join(t.TempDir(), "read")
	if err := os.MkdirAll(readDir, 0o755); err != nil {
		t.Fatalf("create read directory: %v", err)
	}

	readFile := filepath.Join(readDir, "read.txt")
	if err := os.WriteFile(readFile, []byte("keep\n"), 0o644); err != nil {
		t.Fatalf("write read file: %v", err)
	}

	policy := fmt.Sprintf(`
policies:
  - executable: "filepath = %s"
    can_access_dirs:
      - "%s: read"
    can_run:
      - "%s"
`, reader, readDir, reader)

	runAgent(t, policy)

	cmd := exec.Command(reader, command.TruncateMustBeDenied, readFile)

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	if err := cmd.Run(); err != nil {
		t.Fatalf("read-only executable should be denied truncating %s: %v\n%s", readFile, err, out.String())
	}
	if out.String() != "keep\n" {
		t.Fatalf("%s was truncated: got %q", readFile, out.String())
	}
}

// TestTruncateOverwritesWithoutAgent checks that O_RDONLY|O_TRUNC and truncate(2)
// empty a file when the agent is not running.
func TestTruncateOverwritesWithoutAgent(t *testing.T) {
	exe := buildTestBinary(t)
	dir := t.TempDir()

	for _, mode := range []string{"open", "syscall"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(dir, mode+".txt")
			if err := os.WriteFile(path, []byte("keep\n"), 0o644); err != nil {
				t.Fatalf("write %s: %v", path, err)
			}

			cmd := exec.Command(exe, command.Truncate, mode, path)
			var out bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &out
			if err := cmd.Run(); err != nil {
				t.Fatalf("%s should empty %s when the agent is not running: %v\n%s", mode, path, err, out.String())
			}

			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			if len(data) != 0 {
				t.Fatalf("%s was not emptied by %s: got %q", path, mode, data)
			}
		})
	}
}
