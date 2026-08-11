// dual-connect-test checks that a process cannot connect after a prior policy violation.
//
// Manual test (requires root, BPF LSM, agent built with latest trace.c):
//
//	# Terminal 1 — allowed listener (must match config can_only_access_ips)
//	nc -l 127.0.0.1 19001
//
//	# Terminal 2 — blocked listener (not in policy)
//	nc -l 127.0.0.1 19002
//
//	# Terminal 3 — build and install test binary at the path in the config
//	go build -o /tmp/dual-connect-test .
//	sudo make -C .. build-bpf build-agent
//	sudo ../agent --config ../example/config-dual-connect-test.yaml
//
//	# Terminal 4 — run test (same process: blocked connect first, then allowed)
//	sudo /tmp/dual-connect-test
//
// Expect: step 1 fails with EPERM (IP policy), step 2 also fails with EPERM (post-violation connect guard).
// Agent must use flags.security_level: sandbox (or kill).
package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"
)

const (
	defaultAllowedHost = "127.0.0.1"
	defaultAllowedPort = 19001
	defaultBlockedHost = "127.0.0.1"
	defaultBlockedPort = 19002
)

func dialTCP4(host string, port int) error {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp4", addr, 2*time.Second)
	if err != nil {
		return err
	}
	return conn.Close()
}

func isEPERM(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == syscall.EPERM
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Err != nil {
		if errors.As(opErr.Err, &errno) {
			return errno == syscall.EPERM
		}
	}
	return false
}

func parsePort(name, value string) (int, error) {
	port, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("parse %s port %q: %w", name, value, err)
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("%s port out of range: %d", name, port)
	}
	return port, nil
}

func main() {
	allowedHost := defaultAllowedHost
	allowedPort := defaultAllowedPort
	blockedHost := defaultBlockedHost
	blockedPort := defaultBlockedPort

	switch len(os.Args) {
	case 1:
	case 5:
		allowedHost = os.Args[1]
		var err error
		allowedPort, err = parsePort("allowed", os.Args[2])
		if err != nil {
			fmt.Println(err)
			os.Exit(2)
		}
		blockedHost = os.Args[3]
		blockedPort, err = parsePort("blocked", os.Args[4])
		if err != nil {
			fmt.Println(err)
			os.Exit(2)
		}
	default:
		fmt.Fprintf(os.Stderr, "usage: %s [allowed-host allowed-port blocked-host blocked-port]\n", os.Args[0])
		os.Exit(2)
	}

	fmt.Println("=== dual-connect-test ===")
	fmt.Printf("allowed (in policy): %s:%d\n", allowedHost, allowedPort)
	fmt.Printf("blocked (not in policy): %s:%d\n", blockedHost, blockedPort)
	fmt.Println()

	fmt.Printf("step 1: connect to blocked destination %s:%d\n", blockedHost, blockedPort)
	if err := dialTCP4(blockedHost, blockedPort); err != nil {
		fmt.Printf("  result: blocked (%v)\n", err)
		if !isEPERM(err) {
			fmt.Println()
			fmt.Println("FAIL: expected EPERM from IP policy block; got a different error")
			fmt.Println("      (is the agent running with sandbox security_level and listeners up?)")
			os.Exit(1)
		}
	} else {
		fmt.Println("  result: UNEXPECTED success — is the agent running with IP policy?")
		os.Exit(2)
	}
	fmt.Println()

	fmt.Printf("step 2: connect to allowed destination %s:%d (same process, after violation)\n", allowedHost, allowedPort)
	if err := dialTCP4(allowedHost, allowedPort); err != nil {
		fmt.Printf("  result: blocked (%v)\n", err)
		if isEPERM(err) {
			fmt.Println()
			fmt.Println("PASS: connect returned EPERM after prior violation")
			os.Exit(0)
		}
		fmt.Println()
		fmt.Println("FAIL: expected EPERM from post-violation connect guard; got a different error")
		os.Exit(1)
	}

	fmt.Println("  result: UNEXPECTED success")
	fmt.Println()
	fmt.Println("FAIL: process connected to allowed destination after prior violation")
	os.Exit(1)
}
