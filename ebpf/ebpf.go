package ebpf

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	INPUT_PATH_MAX = 1024
	BOOT_ID_MAX    = 41
	TASK_COMM_LEN  = 16
	MAX_EXACT_ARGS = 64
	MAX_ARGS       = MAX_EXACT_ARGS + 1
	MAX_ARG_LEN    = 128
	LSM_LIST_PATH  = "/sys/kernel/security/lsm"
	LSM_BPF_MODULE = "bpf"
	// lsm/bpf hook signature changed in Linux 6.15:
	// - v6.14: LSM_HOOK(int, 0, bpf, int cmd, union bpf_attr *attr, unsigned int size)
	// - v6.15: LSM_HOOK(int, 0, bpf, int cmd, union bpf_attr *attr, unsigned int size, bool kernel)
	// Source:
	// - https://raw.githubusercontent.com/torvalds/linux/v6.14/include/linux/lsm_hook_defs.h
	// - https://raw.githubusercontent.com/torvalds/linux/v6.15/include/linux/lsm_hook_defs.h
	LSMBPFCutoverCode = (6 << 16) | (15 << 8)
	LSMBPFProgramName = "lsm_bpf"
	LSMBPFCompatName  = "lsm_bpf_compat"

	// bpf_get_fsverity_digest kfunc was introduced in Linux 6.8.
	// On older kernels the kfunc is declared __weak and resolves to NULL,
	// so fs-verity digest pinning is silently disabled.
	FsVerityMinKernelCode = (6 << 16) | (8 << 8)
)

var (
	ErrPermissionDenied        = errors.New("eBPF programs require root privileges")
	ErrKernelUnsupported       = errors.New("kernel version does not support eBPF LSM (need >= 5.17)")
	ErrLSMNotConfigured        = errors.New("LSM not configured in GRUB")
	ErrRebootRequired          = errors.New("system reboot required after GRUB configuration")
	ErrEBPFNotSupported        = errors.New("eBPF not supported on this system")
	ErrProgramLoad             = errors.New("failed to load eBPF program")
	ErrInvalidConfiguration    = errors.New("invalid eBPF configuration")
	ErrMemlockRemoval          = errors.New("failed to remove memory lock limit")
	ErrTracepointUnsupported   = errors.New("RawTracepointWritable program type not supported")
	ErrLSMUnsupported          = errors.New("LSM program type not supported")
	ErrProgramTypeCheck        = errors.New("error checking program type support")
	ErrResourcesNotInitialized = errors.New("eBPF resources not initialized")
	ErrEventProcessorCreation  = errors.New("failed to create event processors")
	ErrInvalidPolicyID         = errors.New("policy ID not assigned during setup")
	ErrLoopUnsupported         = errors.New("loop helper not supported in eBPF LSM, need >= 5.17")
	ErrLSMNotEnabled           = errors.New("bpf lsm not enabled")
	ErrRebootRequiredForBPFLSM = errors.New("system reboot required after GRUB configuration for bpf lsm")
)

// ----------------- eBPF map names -----------------

const (
	AllowedPtraceExecutablesMapName      = "bomfather_allowed_ptrace_executables"
	IPToIDMapName                        = "bomfather_ip_to_id"
	ExclusiveIPMaskMapName               = "bomfather_exclusive_ip_mask"
	OpenatEventsMapName                  = "bomfather_openat_events"
	ExecveEventsMapName                  = "bomfather_execve_events"
	ViolationEventsMapName               = "bomfather_log_failures"
	ContainerIDToContainerContextMapName = "bomfather_container_id_to_container_context"
	CgroupIDToContainerContextMapName    = "bomfather_cgroup_id_to_container_context"
	ShouldStopLDEnvMapName               = "bomfather_should_stop_ld_env"
	FileOpenJumpTableMapName             = "bomfather_file_open_jump_table"
	MountCheckJumpTableMapName           = "bomfather_mount_check_jump_table"
	ShouldOutputOpenatsMapName           = "bomfather_should_output_openats"
	UserspaceProcessPIDMapName           = "bomfather_userspace_process_pid"
	ShouldSecureMapsMapName              = "bomfather_should_secure_maps"
	ShouldStopShutdownMapName            = "bomfather_should_stop_shutdown"
	GlobalReadOnlyMapName                = "bomfather_global_read_only"
	BootIDMapName                        = "bomfather_boot_id"
	DebugPrintingMapName                 = "bomfather_debug_config"
	TrustedExecutablesMapName            = "bomfather_trusted_executables"
	PythonIdentifierMapName              = "bomfather_python_identifier_id"
	DirToIDMapName                       = "bomfather_dir_to_id"
	ExecutableToIDMapName                = "bomfather_executable_to_id"
	RestrictGPUMapName                   = "bomfather_restrict_gpu_access"
	BlockPtraceMapName                   = "bomfather_block_ptrace"
	BlockInMemoryExecMapName             = "bomfather_block_in_memory_exec"
	LDEnvAllowedExecutablesMapName       = "bomfather_ld_env_allowed_executables"
	SecurityLevelMapName                 = "bomfather_security_level"
	RestrictBPFOpsMapName                = "bomfather_restrict_bpf_ops"
	FsVerityPinlistMapName               = "bomfather_fsverity_pinlist"
)

type Program interface{}

type TracepointProgram struct {
	TracepointCategory string
	TracepointName     string
	ProgName           string
}

type LSMProgram struct {
	ProgName string // Name of the eBPF program to attach
}

// ----------------- Map inputs from config -----------------

type MapEntry struct {
	Key   any
	Value any
}

type EBPFMapWrite struct {
	MapName string
	Entries map[any]any
}

// ----------------- EBPF Resources -----------------

type EBPFSource interface {
	Read() ([]byte, error)
	Close() error
}

type OpenatSource struct {
	Reader *ringbuf.Reader
}

func (s *OpenatSource) Read() ([]byte, error) {
	record, err := s.Reader.Read()
	if err != nil {
		return nil, err
	}
	return record.RawSample, nil
}

func (s *OpenatSource) Close() error {
	return s.Reader.Close()
}

type ExecveSource struct {
	Reader *perf.Reader
}

func (s *ExecveSource) Read() ([]byte, error) {
	record, err := s.Reader.Read()
	if err != nil {
		return nil, err
	}
	return record.RawSample, nil
}

func (s *ExecveSource) Close() error {
	return s.Reader.Close()
}

type ViolationSource struct {
	Reader *ringbuf.Reader
}

func (s *ViolationSource) Read() ([]byte, error) {
	record, err := s.Reader.Read()
	if err != nil {
		return nil, err
	}
	return record.RawSample, nil
}

func (s *ViolationSource) Close() error {
	return s.Reader.Close()
}

type EBPFResources struct {
	OpenatSource    *OpenatSource    // Specific source for openat events
	ExecveSource    *ExecveSource    // Specific source for execve events
	ViolationSource *ViolationSource // Specific source for violation events
	Links           []link.Link      // Links to the tracepoints
	Collection      *ebpf.Collection // Collection of eBPF programs and maps
}

var basePrograms = []Program{
	&LSMProgram{ProgName: "lsm_file_open"},
	&LSMProgram{ProgName: "lsm_inode_permission"},
	&LSMProgram{ProgName: "lsm_path_rename"},
	&LSMProgram{ProgName: "lsm_path_unlink"},
	&LSMProgram{ProgName: "lsm_path_rmdir"},
	&LSMProgram{ProgName: "lsm_task_alloc"},
	// &LSMProgram{ProgName: "lsm_file_permission"},
	&LSMProgram{ProgName: "lsm_bprm_check_security"},
	&LSMProgram{ProgName: "lsm_ptrace_access_check"},
	&LSMProgram{ProgName: "lsm_socket_connect"},
	&LSMProgram{ProgName: "lsm_sb_mount"},
	&LSMProgram{ProgName: "lsm_mmap_file"},
	&LSMProgram{ProgName: "lsm_socket_recvmsg"},
	&LSMProgram{ProgName: "lsm_socket_sendmsg"},
	&TracepointProgram{
		ProgName:           "trace_execve",
		TracepointCategory: "syscalls",
		TracepointName:     "sys_enter_execve",
	},
	&TracepointProgram{
		ProgName:           "trace_cgroup_mkdir",
		TracepointCategory: "cgroup",
		TracepointName:     "cgroup_mkdir",
	},
	&TracepointProgram{
		ProgName:           "trace_cgroup_rmdir",
		TracepointCategory: "cgroup",
		TracepointName:     "cgroup_rmdir",
	},
	&TracepointProgram{
		ProgName:           "tp_exit_openat",
		TracepointCategory: "syscalls",
		TracepointName:     "sys_exit_openat",
	},
	&TracepointProgram{
		ProgName:           "tp_exit_openat2",
		TracepointCategory: "syscalls",
		TracepointName:     "sys_exit_openat2",
	},
	&TracepointProgram{
		ProgName:           "tp_sched_process_exit",
		TracepointCategory: "sched",
		TracepointName:     "sched_process_exit",
	},
}

var programs = append([]Program(nil), basePrograms...)

func (r *EBPFResources) Close() {
	cleanupResources(r.Collection, r.Links)
	r.OpenatSource.Close()
	r.ExecveSource.Close()
	r.ViolationSource.Close()
}

// checkPrerequisites checks if the system has the necessary prerequisites for eBPF programs
// It checks if the LSM program type is supported and if the loop helper is supported
func checkPrerequisites() error {
	if err := features.HaveProgramType(ebpf.LSM); err != nil {
		return fmt.Errorf("%w: %v", ErrLSMUnsupported, err)
	}

	//checks if the loop helper is supported
	if err := features.HaveProgramHelper(ebpf.RawTracepointWritable, asm.FnLoop); err != nil {
		return fmt.Errorf("%w: %v", ErrLoopUnsupported, err)
	}

	// checks if the LSM is enabled
	b, err := os.ReadFile(LSM_LIST_PATH)
	if err != nil {
		return fmt.Errorf("%w: read %s: %w", ErrLSMNotEnabled, LSM_LIST_PATH, err)
	}
	lsmList := strings.TrimSpace(string(b))
	bpfEnabled := false
	for _, v := range strings.Split(lsmList, ",") {
		if strings.TrimSpace(v) == LSM_BPF_MODULE {
			bpfEnabled = true
			break
		}
	}
	if !bpfEnabled {
		return fmt.Errorf("%w: bpf lsm not enabled; %s=%q", ErrLSMNotEnabled, LSM_LIST_PATH, lsmList)
	}

	// checks if the system needs to be rebooted to apply the LSM GRUB configuration
	cmdline, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return fmt.Errorf("%w: read /proc/cmdline: %w", ErrRebootRequiredForBPFLSM, err)
	}

	hasLSMArg, hasBPFModule := parseLSMKernelArg(string(cmdline))
	if !hasLSMArg {
		return nil
	}
	if hasBPFModule {
		return nil
	}
	return fmt.Errorf("%w", ErrRebootRequiredForBPFLSM)
}

// parseLSMKernelArg parses the LSM kernel argument from the command line
// It returns true if the LSM argument is present and false if it is not
// It returns true if the BPF module is present and false if it is not
func parseLSMKernelArg(cmdline string) (hasLSMArg bool, hasBPFModule bool) {
	fields := strings.Fields(strings.TrimSpace(cmdline))
	for _, field := range fields {
		if !strings.HasPrefix(field, "lsm=") {
			continue
		}
		hasLSMArg = true
		value := strings.TrimPrefix(field, "lsm=")
		for _, module := range strings.Split(value, ",") {
			if strings.TrimSpace(module) == LSM_BPF_MODULE {
				return true, true
			}
		}
	}
	return hasLSMArg, false
}

func isKernel615Plus() (bool, error) {
	// LinuxVersionCode returns LINUX_VERSION_CODE for the running kernel.
	// API docs: https://pkg.go.dev/github.com/cilium/ebpf/features#LinuxVersionCode
	versionCode, err := features.LinuxVersionCode()
	if err != nil {
		return false, fmt.Errorf("get linux version code: %w", err)
	}

	return versionCode >= LSMBPFCutoverCode, nil
}

// IsFsVeritySupported reports whether the running kernel supports the
// bpf_get_fsverity_digest kfunc (Linux >= 6.8).
func IsFsVeritySupported() (bool, error) {
	versionCode, err := features.LinuxVersionCode()
	if err != nil {
		return false, fmt.Errorf("get linux version code: %w", err)
	}
	return versionCode >= FsVerityMinKernelCode, nil
}

func selectBPFProgram(kernel615Plus bool, disableBPFOps bool) (programName string, enabled bool) {
	if disableBPFOps {
		return "", false
	}

	if kernel615Plus {
		return LSMBPFProgramName, true
	}

	return LSMBPFCompatName, true
}

func pruneBPFPrograms(spec *ebpf.CollectionSpec, kernel615Plus bool, disableBPFOps bool) {
	if disableBPFOps {
		delete(spec.Programs, LSMBPFProgramName)
		delete(spec.Programs, LSMBPFCompatName)
		return
	}

	if kernel615Plus {
		delete(spec.Programs, LSMBPFCompatName)
		return
	}

	delete(spec.Programs, LSMBPFProgramName)
}

// loadeBPFFCollection prepares an eBPF collection from compiled program bytes.
//
// It performs the minimum setup required before attaching any programs:
//  1. Removes the memlock limit so kernel map/program allocations can succeed.
//  2. Parses the embedded ELF/object bytes into a collection spec.
//  3. Instantiates the concrete eBPF collection (maps + programs) from that spec.
//
// The returned collection is ready for later setup steps such as writing map
// entries and attaching LSM/tracepoint programs.
func loadEBPFCollection(bpfProgram []byte, kernel615Plus bool, disableBPFOps bool) (*ebpf.Collection, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMemlockRemoval, err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfProgram))
	if err != nil {
		return nil, fmt.Errorf("failed to load eBPF program: %w", err)
	}

	pruneBPFPrograms(spec, kernel615Plus, disableBPFOps)

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("failed to create eBPF collection: %w", err)
	}

	return coll, nil
}

func cleanupResources(coll *ebpf.Collection, links []link.Link) {
	for _, link := range links {
		link.Close()
	}
	coll.Close()
}

func attachPrograms(coll *ebpf.Collection) ([]link.Link, error) {
	programLinks := make([]link.Link, 0, len(programs))

	for _, program := range programs {
		var (
			progLink link.Link
			err      error
			progName string
		)

		switch p := program.(type) {
		case *TracepointProgram:
			progName = p.ProgName
			prog, exists := coll.Programs[progName]
			if !exists {
				break
			}
			progLink, err = link.Tracepoint(p.TracepointCategory, p.TracepointName, prog, nil)

		case *LSMProgram:
			progName = p.ProgName
			prog, exists := coll.Programs[progName]
			if !exists {
				break
			}
			progLink, err = link.AttachLSM(link.LSMOptions{Program: prog})
		}

		if progLink == nil {
			cleanupResources(coll, programLinks)
			return nil, fmt.Errorf("program %q not found or failed to attach", progName)
		}

		if err != nil {
			cleanupResources(coll, programLinks)
			return nil, fmt.Errorf("failed to attach program %q: %w", progName, err)
		}

		programLinks = append(programLinks, progLink)
	}

	return programLinks, nil
}

func createEventSources(coll *ebpf.Collection, programLinks []link.Link) (*ringbuf.Reader, *perf.Reader, *ringbuf.Reader, error) {
	perfBufferSize := os.Getpagesize() * 1024
	// Simplified reader creation with consolidated error handling
	openatReader, err := ringbuf.NewReader(coll.Maps[OpenatEventsMapName])
	if err != nil {
		cleanupResources(coll, programLinks)
		return nil, nil, nil, fmt.Errorf("failed to create ring buffer reader: %w", err)
	}

	execveReader, err := perf.NewReader(coll.Maps[ExecveEventsMapName], perfBufferSize)
	if err != nil {
		openatReader.Close()
		cleanupResources(coll, programLinks)
		return nil, nil, nil, fmt.Errorf("failed to create perf reader: %w", err)
	}

	violationReader, err := ringbuf.NewReader(coll.Maps[ViolationEventsMapName])
	if err != nil {
		execveReader.Close()
		openatReader.Close()
		cleanupResources(coll, programLinks)
		return nil, nil, nil, fmt.Errorf("failed to create ring buffer reader: %w", err)
	}

	// Create sources using the simplified wrapper types
	return openatReader, execveReader, violationReader, nil
}

func UpdateMap(coll *ebpf.Collection, mapName string, key interface{}, value interface{}) error {
	m, ok := coll.Maps[mapName]
	if !ok {
		return fmt.Errorf("map %q not found", mapName)
	}

	if err := m.Update(key, value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update map %q: %w", mapName, err)
	}

	return nil
}

func DeleteKeyFromMap(coll *ebpf.Collection, mapName string, key interface{}) error {
	m, ok := coll.Maps[mapName]
	if !ok {
		return fmt.Errorf("map %q not found", mapName)
	}
	return m.Delete(key)
}

func ReplaceMapEntries[K comparable, V any](coll *ebpf.Collection, mapName string, entries map[any]any) error {
	m, ok := coll.Maps[mapName]
	if !ok {
		return fmt.Errorf("map %q not found", mapName)
	}

	it := m.Iterate()
	var key K
	var value V
	keys := make([]K, 0)
	for it.Next(&key, &value) {
		keys = append(keys, key)
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("failed to iterate map %q: %w", mapName, err)
	}
	for _, key := range keys {
		if err := m.Delete(key); err != nil {
			return fmt.Errorf("failed to clear map %q: %w", mapName, err)
		}
	}

	for key, value := range entries {
		if err := m.Update(key, value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("failed to refresh map %q: %w", mapName, err)
		}
	}
	return nil
}

func setupJumpTable(coll *ebpf.Collection) error {
	fileOpenTailCalls := []string{"tail_call_gpu", "tail_call_security_check", "tail_call_send_data"}
	for index, entry := range fileOpenTailCalls {
		prog, exists := coll.Programs[entry]
		if !exists {
			return fmt.Errorf("%s program not found", entry)
		}

		if err := UpdateMap(coll, FileOpenJumpTableMapName, uint32(index), uint32(prog.FD())); err != nil {
			return err
		}
	}

	mountCheckTailCalls := []string{"tail_call_mount_check"}
	for index, entry := range mountCheckTailCalls {
		prog, exists := coll.Programs[entry]
		if !exists {
			return fmt.Errorf("%s program not found", entry)
		}

		if err := UpdateMap(coll, MountCheckJumpTableMapName, uint32(index), uint32(prog.FD())); err != nil {
			return err
		}
	}

	return nil
}

// setupMutex is used to synchronize access to the eBPF resources,
// so that no other process can go through the setup process at the same time.
var setupMutex sync.Mutex

func InitializeEBPF(bpfProgram []byte, mapWrites []EBPFMapWrite, hasSecureShutdown, shouldSecureMaps, disableBPFOps bool) (*EBPFResources, error) {

	setupMutex.Lock()
	defer setupMutex.Unlock()

	if err := checkPrerequisites(); err != nil {
		return nil, err
	}

	kernel615Plus, err := isKernel615Plus()
	if err != nil {
		return nil, fmt.Errorf("%w: determine kernel version: %v", ErrKernelUnsupported, err)
	}

	coll, err := loadEBPFCollection(bpfProgram, kernel615Plus, disableBPFOps)
	if err != nil {
		return nil, err
	}

	programs = append([]Program(nil), basePrograms...)
	if shouldSecureMaps {
		programs = append(programs, &LSMProgram{ProgName: "lsm_bpf_map"})
	}
	if hasSecureShutdown {
		programs = append(programs, &LSMProgram{ProgName: "lsm_task_kill"})
	}
	bpfProgName, bpfProgEnabled := selectBPFProgram(kernel615Plus, disableBPFOps)
	if bpfProgEnabled {
		programs = append(programs, &LSMProgram{ProgName: bpfProgName})
	}

	for _, mapWrite := range mapWrites {
		for key, value := range mapWrite.Entries {
			if err := UpdateMap(coll, mapWrite.MapName, key, value); err != nil {
				coll.Close()
				return nil, fmt.Errorf("failed to update map %q: %w", mapWrite.MapName, err)
			}
		}
	}

	// Jump table
	if err := setupJumpTable(coll); err != nil {
		coll.Close()
		return nil, fmt.Errorf("failed to setup jump table: %w", err)
	}

	programLinks, err := attachPrograms(coll)
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("failed to attach programs: %w", err)
	}

	openatSource, execveSource, violationSource, err := createEventSources(coll, programLinks)
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("failed to create event sources: %w", err)
	}

	return &EBPFResources{
		OpenatSource:    &OpenatSource{Reader: openatSource},
		ExecveSource:    &ExecveSource{Reader: execveSource},
		ViolationSource: &ViolationSource{Reader: violationSource},
		Links:           programLinks,
		Collection:      coll,
	}, nil
}
