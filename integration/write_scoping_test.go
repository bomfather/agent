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
