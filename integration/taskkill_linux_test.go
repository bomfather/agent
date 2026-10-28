package integration

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/bomfather/bomfather/agent/integration/testdata/command"
)

func TestNonLeaderThreadKillBlocked(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}

	// create the shutdown key
	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubPath := filepath.Join(dir, "shutdown.pub")
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644); err != nil {
		t.Fatalf("write key: %v", err)
	}

	// start the agent
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	agent := runAgentInDir(t, dir, fmt.Sprintf(`
flags:
  security_level: "block"
shutdown_config:
  port: "%d"
  public_key: "%s"
`, port, pubPath))
	t.Cleanup(func() {
		if err := requestShutdown(port, key); err != nil {
			t.Errorf("shutdown: %v", err)
		}
	})

	// The agent is running with shutdown protection, so we should not be able to tgkill with a secondary thread.
	pid := agent.Cmd.Process.Pid
	tid := nonLeaderTid(t, pid)
	if code := runPtraceHelper(t, buildTestBinary(t), command.Tgkill, strconv.Itoa(pid), strconv.Itoa(tid)); code != command.ExitBlocked {
		t.Fatalf("tgkill of non-leader thread %d should be blocked, got exit %d (want %d)", tid, code, command.ExitBlocked)
	}
}

func nonLeaderTid(t *testing.T, pid int) int {
	t.Helper()
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		t.Fatalf("read tasks: %v", err)
	}
	for _, entry := range entries {
		tid, err := strconv.Atoi(entry.Name())
		if err == nil && tid != pid {
			return tid
		}
	}
	t.Fatalf("agent %d has no non-leader thread", pid)
	return 0
}

// Actually shutdown the agent
func requestShutdown(port int, key *rsa.PrivateKey) error {
	var challenge struct {
		Nonce string `json:"nonce"`
	}
	resp, err := http.Post(fmt.Sprintf("http://127.0.0.1:%d/request", port), "application/json", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&challenge); err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(challenge.Nonce))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]string{
		"nonce":     challenge.Nonce,
		"signature": base64.StdEncoding.EncodeToString(sig),
	})
	if err != nil {
		return err
	}
	resp, err = http.Post(fmt.Sprintf("http://127.0.0.1:%d/stop", port), "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("stop: %s", resp.Status)
	}
	return nil
}
