package integration

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"

	"github.com/bomfather/bomfather/agent/integration/testdata/command"
)

func TestCanOnlyAccessIPsRestrictsEgress(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test must be run as root")
	}

	h := buildTestBinary(t)

	// These two IPs are on different ports
	allowedLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen allowed: %v", err)
	}
	defer allowedLn.Close()

	blockedLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen blocked: %v", err)
	}
	defer blockedLn.Close()

	serve := func(ln net.Listener) {
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				_ = conn.Close()
			}
		}()
	}
	serve(allowedLn)
	serve(blockedLn)

	allowedAddr := allowedLn.Addr().String() // 127.0.0.1:port
	blockedAddr := blockedLn.Addr().String()

	// We should be able to connect to the IPs because the agent hasn't been started yet
	if err := exec.Command(h, command.Connect, allowedAddr).Run(); err != nil {
		t.Skipf("pre-agent allowed control failed: %v", err)
	}
	if err := exec.Command(h, command.Connect, blockedAddr).Run(); err != nil {
		t.Skipf("pre-agent blocked control failed: %v", err)
	}

	policy := fmt.Sprintf(`
policies:
  - executable: "filepath = %s"
    can_run:
      - "%s"

attributes:
  - path: "type = executable | filepath = %s"
    can_only_access_ips:
      - "%s"
`, h, h, h, allowedAddr)

	runAgent(t, policy)

	if err := exec.Command(h, command.Connect, allowedAddr).Run(); err != nil {
		t.Fatalf("helper should be allowed to connect to %s: %v", allowedAddr, err)
	}

	if err := exec.Command(h, command.Connect, blockedAddr).Run(); err == nil {
		t.Fatalf("helper should be denied connecting to %s", blockedAddr)
	}
}
