package integration

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/bomfather/bomfather/agent/integration/testdata/command"
)

// securedPolicy arms both map protections: secure_maps blocks reading
// bomfather_ map names, and disable_bpf_ops: false arms restrict_bpf_ops, whose
// lsm/bpf hook denies BPF_MAP_UPDATE_ELEM by a foreign process.
const securedPolicy = `
flags:
  security_level: "sandbox"
  secure_maps: true
  disable_bpf_ops: false
`

// unsecuredMapsPolicy leaves secure_maps off so a foreign process can read
// bomfather_ map names, isolating the secure_maps behaviour.
const unsecuredMapsPolicy = `
flags:
  security_level: "sandbox"
  secure_maps: false
  disable_bpf_ops: false
`

// unrestrictedBPFOpsPolicy disables the BPF-ops restriction entirely
// (disable_bpf_ops: true leaves restrict_bpf_ops unset), so any process may
// perform BPF_PROG_LOAD without being allowlisted. Note the flag is a
// double-negative: disable_bpf_ops: true means the restriction is OFF.
const unrestrictedBPFOpsPolicy = `
flags:
  security_level: "sandbox"
  secure_maps: true
  disable_bpf_ops: true
`

// bpfOpsAllowlistPolicy returns securedPolicy augmented with an allowed_bpf_ops
// attribute for the given executable path. restrict_bpf_ops stays armed, so any
// foreign process is denied BPF_PROG_LOAD except the allowlisted executable.
func bpfOpsAllowlistPolicy(execPath string) string {
	return fmt.Sprintf(`
flags:
  security_level: "sandbox"
  secure_maps: true
  disable_bpf_ops: false

attributes:
  - path: "type = executable | filepath = %s"
    allowed_bpf_ops: true
`, execPath)
}

// TestMapSecurityBlocksForeignAccess runs the real agent under two policies and
// uses the maps helper (a foreign process) to confirm secure_maps controls
// whether bomfather_ map names are readable, and restrict_bpf_ops blocks writes.
//
// Each scenario runs its own agent and stops it before the next starts, so only
// one agent binds the metrics port at a time.
func TestMapSecurityBlocksForeignAccess(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}

	helper := buildTestBinary(t)

	t.Run("secured: reads and writes are blocked", func(t *testing.T) {
		pid, stop := runMapSecurityAgent(t, securedPolicy)
		defer stop()

		if code := runMapsHelper(t, helper, command.List, pid); code != command.ExitBlocked {
			t.Fatalf("reading bomfather_ map names should be blocked, got exit %d (want %d)", code, command.ExitBlocked)
		}
		if code := runMapsHelper(t, helper, command.Update, pid); code != command.ExitBlocked {
			t.Fatalf("updating a bomfather_ map should be blocked, got exit %d (want %d)", code, command.ExitBlocked)
		}
	})

	t.Run("unsecured maps: reads are allowed", func(t *testing.T) {
		pid, stop := runMapSecurityAgent(t, unsecuredMapsPolicy)
		defer stop()

		if code := runMapsHelper(t, helper, command.List, pid); code != command.ExitAccessible {
			t.Fatalf("reading bomfather_ map names should be allowed, got exit %d (want %d)", code, command.ExitAccessible)
		}
	})
}

// runMapSecurityAgent starts the agent with the given policy and metrics
// disabled, returning its PID (as a string) and a stop function that shuts it
// down. Metrics are disabled so consecutive scenarios never contend for the
// metrics port.
func runMapSecurityAgent(t *testing.T, policy string) (pid string, stop func()) {
	t.Helper()

	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	agentBin := filepath.Join(root, agentBinaryName)
	if info, err := os.Stat(agentBin); err != nil || info.IsDir() {
		t.Fatalf("agent binary not found at %s: %v", agentBin, err)
	}

	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(policy), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.Command(agentBin, "run", "--config", configPath, "--metrics-port", "0")
	cmd.Dir = tempDir
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start agent: %v", err)
	}

	stopped := false
	stop = func() {
		if stopped || cmd.Process == nil {
			return
		}
		stopped = true
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	}
	t.Cleanup(stop)

	waitForAgentReady(t, cmd, &stdout, &stderr)
	return strconv.Itoa(cmd.Process.Pid), stop
}

// runMapsHelper runs the maps helper and returns its exit code.
func runMapsHelper(t *testing.T, helper string, args ...string) int {
	t.Helper()
	cmd := exec.Command(helper, args...)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output

	err := cmd.Run()
	t.Logf("maps %v output:\n%s", args, output.String())
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	t.Fatalf("run maps helper %v: %v\n%s", args, err, output.String())
	return -1
}

func TestBPFProgLoadAllowlist(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}

	helper := buildTestBinary(t)

	t.Run("not allowlisted: load is blocked", func(t *testing.T) {
		_, stop := runMapSecurityAgent(t, securedPolicy)
		defer stop()

		if code := runMapsHelper(t, helper, command.LoadProg); code != command.ExitBlocked {
			t.Fatalf("loading a BPF program should be blocked, got exit %d (want %d)", code, command.ExitBlocked)
		}
	})

	t.Run("allowlisted: load is allowed", func(t *testing.T) {
		_, stop := runMapSecurityAgent(t, bpfOpsAllowlistPolicy(helper))
		defer stop()

		if code := runMapsHelper(t, helper, command.LoadProg); code != command.ExitAccessible {
			t.Fatalf("allowlisted executable should load a BPF program, got exit %d (want %d)", code, command.ExitAccessible)
		}
	})

	t.Run("bpf ops unrestricted: load is allowed without allowlist", func(t *testing.T) {
		_, stop := runMapSecurityAgent(t, unrestrictedBPFOpsPolicy)
		defer stop()

		if code := runMapsHelper(t, helper, command.LoadProg); code != command.ExitAccessible {
			t.Fatalf("load should be allowed when restrict_bpf_ops is off, got exit %d (want %d)", code, command.ExitAccessible)
		}
	})
}
