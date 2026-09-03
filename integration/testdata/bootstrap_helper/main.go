// Bootstrap and fallback integration scenarios. Built once per test process; each
// invocation is a normal ELF executable so agent policy keys match mm->exe_file.
package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/bomfather/bomfather/agent/integration/testdata/bootstrap_helper/command"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "bootstrap_helper: missing subcommand")
		os.Exit(2)
	}
	switch os.Args[1] {
	case command.PreagentParentReadChild:
		preagentParentReadChild()
	case command.ParentReadChild:
		parentReadChild()
	case command.Read:
		read()
	case command.ReadAndBlocked:
		readAndBlocked()
	case command.WriteToReadonly:
		writeToReadonly()
	case command.ReadMustBeDenied:
		readMustBeDenied()
	case command.ParentReadAllowedChildReadDenied:
		parentReadAllowedChildReadDenied()
	case command.FilelessExec:
		filelessExec()
	case command.FilelessRan:
		filelessRan()
	default:
		fmt.Fprintf(os.Stderr, "bootstrap_helper: unknown subcommand %q\n", os.Args[1])
		os.Exit(2)
	}
}

func sleepDurArg(idx int) time.Duration {
	ms, err := strconv.Atoi(os.Args[idx])
	if err != nil {
		fmt.Fprintf(os.Stderr, "bootstrap_helper: bad sleep ms %q: %v\n", os.Args[idx], err)
		os.Exit(2)
	}
	return time.Duration(ms) * time.Millisecond
}

func readFirstLine(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open file %s: %w", path, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return "", fmt.Errorf("scan file %s: %w", path, err)
		}
		return "", fmt.Errorf("empty file %s", path)
	}
	return sc.Text(), nil
}

func mustRead(path string) {
	if _, err := readFirstLine(path); err != nil {
		os.Exit(10)
	}
}

func runChild(exe string, args ...string) {
	cmd := exec.Command(exe, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		os.Exit(11)
	}
}

func readThenExecRead(file, childExe string) {
	mustRead(file)
	runChild(childExe, command.Read, file)
}

func preagentParentReadChild() {
	if len(os.Args) != 5 {
		os.Exit(2)
	}
	time.Sleep(sleepDurArg(2))
	readThenExecRead(os.Args[3], os.Args[4])
}

func parentReadChild() {
	if len(os.Args) != 4 {
		os.Exit(2)
	}
	readThenExecRead(os.Args[2], os.Args[3])
}

// read
func read() {
	if len(os.Args) != 3 {
		os.Exit(2)
	}
	mustRead(os.Args[2])
}

// Read a file which should succeed and then blocked file should not be allowed
func readAndBlocked() {
	if len(os.Args) != 5 {
		os.Exit(2)
	}
	time.Sleep(sleepDurArg(2))
	if _, err := readFirstLine(os.Args[3]); err != nil {
		os.Exit(10)
	}
	if _, err := readFirstLine(os.Args[4]); err == nil {
		os.Exit(11)
	}
}

// Test writing to a readonly file
func writeToReadonly() {
	if len(os.Args) != 4 {
		os.Exit(2)
	}
	time.Sleep(sleepDurArg(2))
	if err := os.WriteFile(os.Args[3], []byte("modified\n"), 0o644); err == nil {
		os.Exit(10)
	}
	if _, err := readFirstLine(os.Args[3]); err != nil {
		os.Exit(11)
	}
}

// readMustBeDenied expects the read to be blocked by policy. If the read
// unexpectedly succeeds, exit 10
// if it is denied as expected, exit 0.
func readMustBeDenied() {
	if len(os.Args) != 3 {
		os.Exit(2)
	}
	if _, err := readFirstLine(os.Args[2]); err == nil {
		os.Exit(10)
	}
}

// parentReadAllowedChildReadDenied proves negative inheritance. The parent reads
// allowedFile (must succeed), then spawns childExe to read blockedFile (must be
// denied). Exit 10 if the parent's allowed read fails; exit 11 if the child is
// able to read the blocked file (i.e. it exceeded the parent's grants).
func parentReadAllowedChildReadDenied() {
	if len(os.Args) != 6 {
		os.Exit(2)
	}
	time.Sleep(sleepDurArg(2))
	allowedFile := os.Args[3]
	blockedFile := os.Args[4]
	childExe := os.Args[5]

	if _, err := readFirstLine(allowedFile); err != nil {
		os.Exit(10)
	}
	// The child must be denied blockedFile.
	runChild(childExe, command.ReadMustBeDenied, blockedFile)
}

// filelessExec copies this binary into an anonymous in-memory file (memfd) and
// tries to execute it. The kernel exposes the memfd image as "memfd:...", which
// the agent treats as a fileless execution. If the exec is blocked, control
// returns here and we exit 0 (correctly denied). If the exec succeeds, the
// in-memory image replaces this process and runs the FilelessRan sentinel.
func filelessExec() {
	self, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		fmt.Fprintf(os.Stderr, "bootstrap_helper: read self: %v\n", err)
		os.Exit(2)
	}

	// flags = 0 (no MFD_CLOEXEC) so the descriptor survives execve.
	fd, err := unix.MemfdCreate("bomfather-fileless", 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bootstrap_helper: memfd_create: %v\n", err)
		os.Exit(2)
	}
	if _, err := unix.Write(fd, self); err != nil {
		fmt.Fprintf(os.Stderr, "bootstrap_helper: write memfd: %v\n", err)
		os.Exit(2)
	}

	path := fmt.Sprintf("/proc/self/fd/%d", fd)
	// If Exec succeeds the image is replaced and FilelessRan runs (exit 12).
	// If it returns, execution was blocked -> correctly denied.
	execErr := syscall.Exec(path, []string{path, command.FilelessRan}, os.Environ())
	fmt.Fprintf(os.Stderr, "bootstrap_helper: fileless exec blocked: %v\n", execErr)
	os.Exit(0)
}

// filelessRan is the sentinel the in-memory image runs when fileless execution
// was NOT blocked. Exit 12 signals that the fileless exec succeeded, which is a
// failure for the test.
func filelessRan() {
	os.Exit(12)
}
