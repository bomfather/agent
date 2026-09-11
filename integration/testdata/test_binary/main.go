// Shared integration test binary. Built once per test process; each invocation
// is a normal ELF executable so agent policy keys match mm->exe_file.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/bomfather/bomfather/agent/integration/testdata/command"
)

// bomfatherPrefix identifies the agent's BPF maps by name.
const bomfatherPrefix = "bomfather_"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "test_binary: missing subcommand")
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
	case command.Connect:
		connect()
	case command.ReadMustBeDenied:
		readMustBeDenied()
	case command.ParentReadAllowedChildReadDenied:
		parentReadAllowedChildReadDenied()
	case command.FilelessExec:
		filelessExec()
	case command.FilelessRan:
		filelessRan()
	case command.List:
		os.Exit(listMaps(mapsPidArg()))
	case command.Update:
		os.Exit(updateMap(mapsPidArg(), mapsNameArg()))
	default:
		fmt.Fprintf(os.Stderr, "test_binary: unknown subcommand %q\n", os.Args[1])
		os.Exit(2)
	}
}

// mapsPidArg parses the target pid shared by the list and update subcommands
// (test_binary <list|update> PID [MAP_NAME]).
func mapsPidArg() int {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: test_binary list|update PID [MAP_NAME]")
		os.Exit(command.ExitError)
	}
	pid, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid pid %q\n", os.Args[2])
		os.Exit(command.ExitError)
	}
	return pid
}

// mapsNameArg returns the optional map name for the update subcommand, or "" to
// target every candidate map.
func mapsNameArg() string {
	if len(os.Args) > 3 {
		return os.Args[3]
	}
	return ""
}

func sleepDurArg(idx int) time.Duration {
	ms, err := strconv.Atoi(os.Args[idx])
	if err != nil {
		fmt.Fprintf(os.Stderr, "test_binary: bad sleep ms %q: %v\n", os.Args[idx], err)
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

func read() {
	if len(os.Args) != 3 {
		os.Exit(2)
	}
	mustRead(os.Args[2])
}

// readAndBlocked reads an allowed file (must succeed) then a blocked file (must
// be denied), exiting non-zero if either expectation is violated.
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

func connect() {
	if len(os.Args) != 3 {
		os.Exit(2)
	}
	conn, err := net.DialTimeout("tcp4", os.Args[2], 2*time.Second)
	if err != nil {
		os.Exit(10)
	}
	_ = conn.Close()
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
		fmt.Fprintf(os.Stderr, "test_binary: read self: %v\n", err)
		os.Exit(2)
	}

	// flags = 0 (no MFD_CLOEXEC) so the descriptor survives execve.
	fd, err := unix.MemfdCreate("bomfather-fileless", 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "test_binary: memfd_create: %v\n", err)
		os.Exit(2)
	}
	if _, err := unix.Write(fd, self); err != nil {
		fmt.Fprintf(os.Stderr, "test_binary: write memfd: %v\n", err)
		os.Exit(2)
	}

	path := fmt.Sprintf("/proc/self/fd/%d", fd)
	// If Exec succeeds the image is replaced and FilelessRan runs (exit 12).
	// If it returns, execution was blocked -> correctly denied.
	execErr := syscall.Exec(path, []string{path, command.FilelessRan}, os.Environ())
	fmt.Fprintf(os.Stderr, "test_binary: fileless exec blocked: %v\n", execErr)
	os.Exit(0)
}

func filelessRan() {
	os.Exit(12)
}

func listMaps(pid int) int {
	mapIDs, err := scanMapIDs(pid)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return command.ExitError
	}

	readable := 0
	for _, mapID := range mapIDs {
		m, err := ebpf.NewMapFromID(ebpf.MapID(uint32(mapID)))
		if err != nil {
			fmt.Fprintf(os.Stderr, "map_id=%d: %s\n", mapID, reason(err))
			continue
		}
		info, err := m.Info()
		m.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "map_id=%d: %s\n", mapID, reason(err))
			continue
		}
		if strings.HasPrefix(info.Name, bomfatherPrefix) {
			readable++
			fmt.Fprintf(os.Stderr, "map_id=%d name=%s: READABLE\n", mapID, info.Name)
		}
	}

	if readable > 0 {
		fmt.Fprintf(os.Stderr, "read %d bomfather_ map(s)\n", readable)
		return command.ExitAccessible
	}
	fmt.Fprintln(os.Stderr, "no bomfather_ maps readable (blocked)")
	return command.ExitBlocked
}

func updateMap(pid int, wantName string) int {
	fds, err := os.ReadDir(filepath.Join("/proc", strconv.Itoa(pid), "fd"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "read /proc/%d/fd: %v\n", pid, err)
		return command.ExitError
	}

	attempted, denied := 0, 0
	for _, entry := range fds {
		fdID, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		mapID, ok := readMapID(pid, fdID)
		if !ok {
			continue
		}
		if wantName != "" && !nameMatches(mapID, wantName) {
			continue
		}

		switch tryUpdate(pid, fdID, mapID) {
		case command.ExitAccessible:
			return command.ExitAccessible
		case command.ExitBlocked:
			denied++
		}
		attempted++
	}

	if attempted == 0 {
		fmt.Fprintf(os.Stderr, "no matching map fds found for pid %d\n", pid)
		return command.ExitError
	}
	if denied == 0 {
		fmt.Fprintln(os.Stderr, "no update attempt was denied")
		return command.ExitError
	}
	fmt.Fprintf(os.Stderr, "all %d update attempt(s) denied\n", denied)
	return command.ExitBlocked
}

func tryUpdate(pid, fdID, mapID int) int {
	m, err := openMapViaPidfd(pid, fdID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "map_id=%d fd=%d: getfd %s\n", mapID, fdID, reason(err))
		return exitFor(err)
	}
	defer m.Close()

	key := make([]byte, m.KeySize())
	value, err := updateValue(m)
	if err != nil {
		fmt.Fprintf(os.Stderr, "map_id=%d fd=%d: value %v\n", mapID, fdID, err)
		return command.ExitError
	}
	if err := m.Update(key, value, ebpf.UpdateAny); err != nil {
		fmt.Fprintf(os.Stderr, "map_id=%d fd=%d: update %s\n", mapID, fdID, reason(err))
		return exitFor(err)
	}

	fmt.Fprintf(os.Stderr, "map_id=%d fd=%d: UPDATED\n", mapID, fdID)
	return command.ExitAccessible
}

func updateValue(m *ebpf.Map) (any, error) {
	var perCPUValue bool
	switch m.Type() {
	case ebpf.PerCPUHash, ebpf.PerCPUArray, ebpf.LRUCPUHash, ebpf.PerCPUCGroupStorage:
		perCPUValue = true
	}
	if !perCPUValue {
		return make([]byte, m.ValueSize()), nil
	}
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, fmt.Errorf("possible cpus: %w", err)
	}
	perCPU := make([][]byte, cpus)
	for i := range perCPU {
		perCPU[i] = make([]byte, m.ValueSize())
	}
	return perCPU, nil
}

func nameMatches(mapID int, wantName string) bool {
	m, err := ebpf.NewMapFromID(ebpf.MapID(uint32(mapID)))
	if err != nil {
		return false
	}
	info, err := m.Info()
	m.Close()
	return err == nil && info.Name == wantName
}

func scanMapIDs(pid int) ([]int, error) {
	fds, err := os.ReadDir(filepath.Join("/proc", strconv.Itoa(pid), "fd"))
	if err != nil {
		return nil, fmt.Errorf("read /proc/%d/fd: %w", pid, err)
	}
	var ids []int
	for _, entry := range fds {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		if id, ok := readMapID(pid, fd); ok {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("no BPF map fds found for pid %d", pid)
	}
	return ids, nil
}

func openMapViaPidfd(pid, fdID int) (*ebpf.Map, error) {
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(pidfd)

	stolen, err := unix.PidfdGetfd(pidfd, fdID, 0)
	if err != nil {
		return nil, err
	}

	// NewMapFromFD takes ownership of the stolen fd (it does not dup it), so the
	// returned Map closes it via m.Close(). Only close it ourselves if the
	// hand-off fails, otherwise the later Update sees a closed fd (EBADF).
	m, err := ebpf.NewMapFromFD(stolen)
	if err != nil {
		unix.Close(stolen)
		return nil, err
	}
	return m, nil
}

func isDenied(err error) bool {
	return errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES)
}

func exitFor(err error) int {
	if isDenied(err) {
		return command.ExitBlocked
	}
	return command.ExitError
}

func reason(err error) string {
	if isDenied(err) {
		return "denied"
	}
	return err.Error()
}

func readMapID(pid, fdID int) (int, bool) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "fdinfo", strconv.Itoa(fdID)))
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if id, ok := strings.CutPrefix(line, "map_id:"); ok {
			mapID, err := strconv.Atoi(strings.TrimSpace(id))
			return mapID, err == nil
		}
	}
	return 0, false
}
