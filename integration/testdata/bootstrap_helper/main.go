// Bootstrap and fallback integration scenarios. Built once per test process; each
// invocation is a normal ELF executable so agent policy keys match mm->exe_file.
package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"time"

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
