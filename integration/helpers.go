package integration

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const (
	agentReadyLogLine = "eBPF security policies launched successfully"
	timeout           = 10 * time.Second
	agentBinaryName   = "agent"
)

type RunningAgent struct {
	Cmd        *exec.Cmd
	TempDir    string
	ConfigPath string
	Stdout     *bytes.Buffer
	Stderr     *bytes.Buffer
}

var (
	testBinaryOnce sync.Once
	testBinaryPath string
)

// waitForAgentReady waits for the agent to be ready by checking its stdout for a specific log line.
func waitForAgentReady(t *testing.T, cmd *exec.Cmd, stdout, stderr *bytes.Buffer) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if bytes.Contains(stdout.Bytes(), []byte(agentReadyLogLine)) {
			return
		}
		if err := syscall.Kill(cmd.Process.Pid, syscall.Signal(0)); err != nil {
			t.Fatalf("Agent process exited unexpectedly: %v\nStdout: %s\nStderr: %s", err, stdout.String(), stderr.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("Timeout waiting for agent to be ready. Stdout: %s\nStderr: %s", stdout.String(), stderr.String())
}
func runAgent(t *testing.T, config string) *RunningAgent {
	t.Helper()
	return runAgentInDir(t, t.TempDir(), config)
}

// runAgentInDir starts the agent in tempDir with the given configuration YAML
// and registers cleanup.
func runAgentInDir(t *testing.T, tempDir, config string) *RunningAgent {
	t.Helper()

	workingDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current working directory: %v", err)
	}

	agnetDir := filepath.Dir(workingDir)
	agentBinaryPath := filepath.Join(agnetDir, agentBinaryName)

	if info, err := os.Stat(agentBinaryPath); err != nil || info.IsDir() {
		t.Fatalf("Agent binary not found at %s: %v", agentBinaryPath, err)
	}
	configPath := filepath.Join(tempDir, "config.yaml")
	configContents := strings.ReplaceAll(config, "{{TEMP_DIR}}", tempDir)
	if err := os.WriteFile(configPath, []byte(configContents), 0o600); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	stdOut := &bytes.Buffer{}
	stdErr := &bytes.Buffer{}
	cmd := exec.Command(agentBinaryPath, "run", "--config", configPath)
	cmd.Dir = tempDir
	cmd.Stdout = stdOut
	cmd.Stderr = stdErr

	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start agent: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process == nil {
			return
		}
		_ = cmd.Process.Signal(os.Interrupt)

		done := make(chan error, 1)
		go func() {
			done <- cmd.Wait()
		}()

		select {
		case err := <-done:
			if err != nil {
				t.Logf("Agent exited with error: %v\nstdout:%v\nstderr:%v", err, stdOut.String(), stdErr.String())
			}
		case <-time.After(5 * time.Second):
			t.Logf("Agent did not exit in time, killing it. stdout:%v\nstderr:%v", stdOut.String(), stdErr.String())
			_ = cmd.Process.Kill()
			if err := <-done; err != nil {
				t.Logf("Agent exited with error after kill: %v\nstdout:%s\nstderr:%s", err, stdOut.String(), stdErr.String())
			}
		}
	})

	time.Sleep(2 * time.Second)

	if err := syscall.Kill(cmd.Process.Pid, syscall.Signal(0)); err != nil {
		t.Fatalf("Agent process exited unexpectedly: %v\nStdout: %s\nStderr: %s", err, stdOut.String(), stdErr.String())
	}

	waitForAgentReady(t, cmd, stdOut, stdErr)

	return &RunningAgent{
		Cmd:        cmd,
		TempDir:    tempDir,
		ConfigPath: configPath,
		Stdout:     stdOut,
		Stderr:     stdErr,
	}
}

// buildTestBinary builds the shared integration test binary and returns its path.
func buildTestBinary(t *testing.T) string {
	t.Helper()

	testBinaryOnce.Do(func() {
		integrationDir, err := os.Getwd()
		if err != nil {
			t.Fatalf("Failed to get current working directory: %v", err)
		}

		tmpDir, err := os.MkdirTemp("", "bomfather-test-binary-*")
		if err != nil {
			t.Fatalf("Failed to create temporary directory for test binary: %v", err)
		}

		bin := filepath.Join(tmpDir, "integration_test_binary")
		testBinarySrcDir := filepath.Join(integrationDir, "testdata", "test_binary")
		cmd := exec.Command("go", "build", "-o", bin, ".")
		cmd.Dir = testBinarySrcDir
		buildLog, err := cmd.CombinedOutput()
		if err != nil {
			_, _ = os.Stderr.Write(buildLog)
			t.Fatalf("Failed to build test binary: %v", err)
			return
		}

		testBinaryPath = bin
	})

	return testBinaryPath
}

func mustResolveExecutable(t *testing.T, name string) string {
	t.Helper()

	path, err := exec.LookPath(name)
	if err != nil {
		t.Fatalf("find %s executable: %v", name, err)
	}

	resolvedPath, err := filepath.EvalSymlinks(path)
	if err == nil {
		return resolvedPath
	}

	return path
}
