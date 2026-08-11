package config

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/goccy/go-yaml"

	agentebpf "github.com/bomfather/bomfather/agent/ebpf"
)

const (
	bitmaskWords       = 2
	bitmaskBitsPerWord = 32
	maxBitmaskIDs      = bitmaskWords * bitmaskBitsPerWord
)

// --------------- Types for the config file ---------------

type Config struct {
	Policies       []Policy       `yaml:"policies"`
	Attributes     []Attribute    `yaml:"attributes"`
	Flags          Flags          `yaml:"flags"`
	ShutdownConfig ShutdownConfig `yaml:"shutdown_config"`
}

type Policy struct {
	Executable          string   `yaml:"executable"`
	Python              string   `yaml:"python"`
	PythonArgvExact     []string `yaml:"python_argv_exact"`
	PythonCwd           string   `yaml:"python_cwd"`
	Directories         []string `yaml:"can_access_dirs"`
	AllowedExecutables  []string `yaml:"can_run"`
	IsAllowedToAccessIP []string `yaml:"is_allowed_to_access_ip"`
	FsVerityDigest      string   `yaml:"fsverity_digest"`
}

type Flags struct {
	SecureMaps        bool   `yaml:"secure_maps"`
	BlockPtrace       bool   `yaml:"block_ptrace"`
	BlockInMemoryExec bool   `yaml:"block_in_memory_exec"`
	RestrictGPU       bool   `yaml:"restrict_gpu"`
	RestrictLDEnv     bool   `yaml:"restrict_ld_env"`
	EnableOpenat      bool   `yaml:"enable_openat"`
	SecurityLevel     string `yaml:"security_level"`
	DisableBPFOps     bool   `yaml:"disable_bpf_ops"`
}

type ShutdownConfig struct {
	Port      string `yaml:"port"`
	PublicKey string `yaml:"public_key"`
}

type Attribute struct {
	Path             string   `yaml:"path"`
	AllowedLDEnv     bool     `yaml:"allowed_ld_env"`
	AllowedPtrace    bool     `yaml:"allowed_ptrace"`
	AllowedGPU       bool     `yaml:"allowed_gpu"`
	OutputOpenats    bool     `yaml:"output_openats_for_executable"`
	GlobalReadOnly   bool     `yaml:"global_read_only"`
	CanOnlyAccessIPs []string `yaml:"can_only_access_ips"`
}

// --------------- Types for parsing paths in the config file ---------------

type Path struct {
	Type          string
	ContainerPath string
	FilePath      string
}

type PythonPolicy struct {
	FilePath      string
	Libs          []string
	ContainerPath string
}

type Container struct {
	Namespace string
	Pod       string
	Container string
}

// --------------- Types for the eBPF maps ---------------

// PathKey mirrors the C struct path_key used in bomfather_trusted_executables.
type PathKey struct {
	PolicyID      uint32
	DirectoryPath [agentebpf.INPUT_PATH_MAX]byte
}

// FsVerityAllowlistKey mirrors the C struct fsverity_allowlist_key.
// Algorithm constants match the kernel's FS_VERITY_HASH_ALG_* values.
// SHA-256 = 1. Digest is always 64 bytes; SHA-256 uses the first 32, rest zero.
type FsVerityAllowlistKey struct {
	Alg    uint16
	Digest [64]byte
}

const fsVerityAlgSHA256 = uint16(1)

type IPToIDKey struct {
	PolicyID uint32
	DstIPv4  uint32 // network byte order
	DstPort  uint16 // host byte order
	Pad      uint16
}

type BitmaskArray [bitmaskWords]uint32
type AccessControlValue struct {
	Read             BitmaskArray
	Write            BitmaskArray
	Execute          BitmaskArray
	GPU              uint32
	IPEgress         BitmaskArray
	IPExclusiveOwner BitmaskArray
	OutputOpenats    uint32
}

// --------------- Types for the policy ID mapper ---------------

type PolicyIDMapper struct {
	pathToID map[any]uint32
	nextID   uint32
}

type NetworkToConvert struct {
	policyID          uint32
	networkConnection string
}

func NewPolicyIDMapper() *PolicyIDMapper {
	return &PolicyIDMapper{pathToID: make(map[any]uint32)}
}

func (m *PolicyIDMapper) GetOrAssign(key any) uint32 {
	// Host (empty path) always gets policy_id 0
	if key == nil {
		return 0
	}

	if id, exists := m.pathToID[key]; exists {
		return id
	}

	m.nextID++
	m.pathToID[key] = m.nextID
	return m.nextID
}

func (m *PolicyIDMapper) Set(key any, value uint32) {
	m.pathToID[key] = value
}

func (m *PolicyIDMapper) ToMapList(name string) agentebpf.EBPFMapWrite {
	mapList := agentebpf.EBPFMapWrite{MapName: name, Entries: make(map[any]any)}
	for key, value := range m.pathToID {
		mapList.Entries[key] = value
	}
	return mapList
}

func setIDBit(mask *BitmaskArray, id uint32) error {
	if id <= 0 {
		return fmt.Errorf("id must be >= 1, got %d", id)
	}
	zeroBased := id - 1
	word := zeroBased / bitmaskBitsPerWord
	bit := zeroBased % bitmaskBitsPerWord
	if word >= bitmaskWords {
		return fmt.Errorf("id %d exceeds bitmask capacity %d", id, maxBitmaskIDs)
	}
	mask[word] |= (uint32(1) << uint(bit))
	return nil
}

func pathParser(path string) (Path, error) {
	parts := strings.Split(path, "|")

	if len(parts) > 3 {
		return Path{}, fmt.Errorf("Too many parts in path, only expected up to 3 parts, got %d parts in %q, expected type = x | container = y | filepath = z", len(parts), path)
	}

	out := Path{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			return Path{}, fmt.Errorf("invalid path component %q, expected key = value", part)
		}

		key := strings.ToLower(strings.TrimSpace(kv[0]))
		value := strings.TrimSpace(kv[1])

		fieldName := ""
		var current *string

		switch key {
		case "type":
			fieldName = "type"
			current = &out.Type

			if value != "executable" && value != "filepath" {
				return Path{}, fmt.Errorf("invalid type %q, expected executable or filepath", value)
			}
			value = strings.ToLower(value)
		case "container":
			fieldName = "container"
			current = &out.ContainerPath
		case "filepath":
			fieldName = "filepath"
			current = &out.FilePath
		default:
			return Path{}, fmt.Errorf("unsupported key %q", key)
		}

		if *current != "" {
			return Path{}, fmt.Errorf("%s already set to %q, expected only one %s", fieldName, *current, fieldName)
		}
		*current = value // current is a pointer to the field in the out struct
	}

	return out, nil
}

func pythonPolicyParser(policy string) (PythonPolicy, error) {
	parts := strings.Split(policy, "|")

	libs := ""
	pathParts := []string{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			return PythonPolicy{}, fmt.Errorf("invalid python policy component %q, expected key = value", part)
		}

		key := strings.ToLower(strings.TrimSpace(kv[0]))
		value := strings.TrimSpace(kv[1])

		// python specific keys
		if key == "libs" {
			if libs != "" {
				return PythonPolicy{}, fmt.Errorf("libs already set to %q, expected only one libs", libs)
			}
			libs = value
			continue
		}

		pathParts = append(pathParts, part)
	}

	parsedPath, err := pathParser(strings.Join(pathParts, " | "))
	if err != nil {
		return PythonPolicy{}, err
	}

	if parsedPath.FilePath == "" {
		return PythonPolicy{}, fmt.Errorf("filepath is required")
	}
	if libs == "" {
		return PythonPolicy{}, fmt.Errorf("libs is required")
	}
	libPaths := []string{}
	for _, lib := range strings.Split(libs, ",") {
		lib = strings.TrimSpace(lib)
		if lib == "" {
			return PythonPolicy{}, fmt.Errorf("libs contains an empty path")
		}
		libPaths = append(libPaths, lib)
	}

	return PythonPolicy{
		FilePath:      parsedPath.FilePath,
		Libs:          libPaths,
		ContainerPath: parsedPath.ContainerPath,
	}, nil
}

func pythonArgvExactParser(args []string) (*[agentebpf.MAX_ARGS][agentebpf.MAX_ARG_LEN]byte, error) {
	if len(args) == 0 {
		return nil, nil
	}
	if len(args) > agentebpf.MAX_EXACT_ARGS {
		return nil, fmt.Errorf("expected at most %d args, got %d", agentebpf.MAX_EXACT_ARGS, len(args))
	}

	var out [agentebpf.MAX_ARGS][agentebpf.MAX_ARG_LEN]byte
	for i, arg := range args {
		if arg == "" {
			return nil, fmt.Errorf("arg %d cannot be empty", i)
		}
		if strings.IndexByte(arg, 0) != -1 {
			return nil, fmt.Errorf("arg %d contains a null byte", i)
		}
		if len(arg) >= agentebpf.MAX_ARG_LEN {
			return nil, fmt.Errorf("arg %d %q is too long, expected fewer than %d characters", i, arg, agentebpf.MAX_ARG_LEN)
		}
		copy(out[i][:], arg)
	}

	return &out, nil
}

func pythonCwdParser(cwd string) (*[agentebpf.INPUT_PATH_MAX]byte, error) {
	cwd = strings.TrimSpace(cwd)
	if cwd == "" {
		return nil, nil
	}
	if !strings.HasPrefix(cwd, "/") {
		return nil, fmt.Errorf("cwd %q must be an absolute path", cwd)
	}
	if strings.IndexByte(cwd, 0) != -1 {
		return nil, fmt.Errorf("cwd contains a null byte")
	}
	if len(cwd) >= agentebpf.INPUT_PATH_MAX {
		return nil, fmt.Errorf("cwd %q is too long, expected fewer than %d characters", cwd, agentebpf.INPUT_PATH_MAX)
	}

	var out [agentebpf.INPUT_PATH_MAX]byte
	copy(out[:], cwd)
	return &out, nil
}

func validateConfig(config Config) error {
	seenPolicies := make(map[Path]bool)

	for _, policy := range config.Policies {
		executable := policy.Executable
		if strings.TrimSpace(policy.Python) != "" {
			if strings.TrimSpace(executable) != "" {
				return fmt.Errorf("policy cannot set both executable and python")
			}
			parsedPythonPolicy, err := pythonPolicyParser(policy.Python)
			if err != nil {
				return fmt.Errorf("invalid python policy %q: %w", policy.Python, err)
			}
			executable = fmt.Sprintf("filepath = %s | container = %s", parsedPythonPolicy.FilePath, parsedPythonPolicy.ContainerPath)
		} else if len(policy.PythonArgvExact) > 0 {
			return fmt.Errorf("policy cannot set python_argv_exact without python")
		} else if strings.TrimSpace(policy.PythonCwd) != "" {
			return fmt.Errorf("policy cannot set python_cwd without python")
		}

		if strings.TrimSpace(policy.PythonCwd) != "" && len(policy.PythonArgvExact) == 0 {
			return fmt.Errorf("policy cannot set python_cwd without python_argv_exact")
		}

		if _, err := pythonArgvExactParser(policy.PythonArgvExact); err != nil {
			return fmt.Errorf("invalid policy python_argv_exact: %w", err)
		}
		if _, err := pythonCwdParser(policy.PythonCwd); err != nil {
			return fmt.Errorf("invalid policy python_cwd: %w", err)
		}

		parsedPath, err := pathParser(executable)
		if err != nil {
			return fmt.Errorf("invalid policy executable %q: %w", executable, err)
		}
		if parsedPath.Type != "" {
			return fmt.Errorf("type in path should not be set for policy executable %q, got %q", executable, parsedPath.Type)
		}

		normalizedPath := normalizedPathForLookup(parsedPath)
		if seenPolicies[normalizedPath] {
			return fmt.Errorf("policy executable %s is duplicated, each executable can only be defined once, and all polices for that executable must be defined together", executable)
		}

		seenPolicies[normalizedPath] = true
	}

	seenAttributes := make(map[Path]bool)
	for _, attribute := range config.Attributes {
		parsedPath, err := pathParser(attribute.Path)
		if err != nil {
			return fmt.Errorf("invalid attribute path %q: %w", attribute.Path, err)
		}

		normalizedPath := normalizedPathForLookup(parsedPath)
		if seenAttributes[normalizedPath] {
			return fmt.Errorf("attribute path %q is duplicated, each attribute path can only be defined once", attribute.Path)
		}

		seenAttributes[normalizedPath] = true
	}
	return nil
}

func normalizedPathForLookup(parsedPath Path) Path {
	parsedPath.FilePath = strings.TrimRight(strings.TrimSpace(parsedPath.FilePath), string(os.PathSeparator))
	return parsedPath
}

func addToArray(mapsArray []agentebpf.EBPFMapWrite, mapName string, key any, value any) []agentebpf.EBPFMapWrite {
	return append(mapsArray, agentebpf.EBPFMapWrite{MapName: mapName, Entries: map[any]any{key: value}})
}

// parseFsVerityDigest parses a single "sha256:<hex>" string (as produced by
// `fsverity measure`) into a BPF allowlist key.
func parseFsVerityDigest(token string) (FsVerityAllowlistKey, error) {
	alg, hexDigest, found := strings.Cut(strings.TrimSpace(token), ":")
	if !found {
		return FsVerityAllowlistKey{}, fmt.Errorf("invalid fsverity digest %q: expected format sha256:<hex>", token)
	}
	if strings.ToLower(alg) != "sha256" {
		return FsVerityAllowlistKey{}, fmt.Errorf("unsupported fsverity algorithm %q: only sha256 is supported", alg)
	}
	raw, err := hex.DecodeString(hexDigest)
	if err != nil {
		return FsVerityAllowlistKey{}, fmt.Errorf("invalid fsverity digest hex %q: %w", hexDigest, err)
	}
	if len(raw) != 32 {
		return FsVerityAllowlistKey{}, fmt.Errorf("invalid sha256 digest length %d (expected 32 bytes) in %q", len(raw), token)
	}
	key := FsVerityAllowlistKey{Alg: fsVerityAlgSHA256}
	copy(key.Digest[:], raw) // first 32 bytes; remaining 32 stay zero
	return key, nil
}

func basicSetup(config Config, debugEnabled bool) ([]agentebpf.EBPFMapWrite, error) {
	mapsArray := []agentebpf.EBPFMapWrite{}

	switch config.Flags.SecurityLevel {
	case "kill":
		mapsArray = addToArray(mapsArray, agentebpf.SecurityLevelMapName, uint32(0), uint32(3))
	case "sandbox":
		mapsArray = addToArray(mapsArray, agentebpf.SecurityLevelMapName, uint32(0), uint32(2))
	case "block", "":
		mapsArray = addToArray(mapsArray, agentebpf.SecurityLevelMapName, uint32(0), uint32(1))
	case "monitor":
		mapsArray = addToArray(mapsArray, agentebpf.SecurityLevelMapName, uint32(0), uint32(0))
	default:
		return nil, fmt.Errorf("invalid security level %q, expected kill, sandbox, block, or empty", config.Flags.SecurityLevel)
	}
	if debugEnabled {
		mapsArray = addToArray(mapsArray, agentebpf.DebugPrintingMapName, uint32(0), true)
	}
	if config.Flags.SecureMaps {
		mapsArray = addToArray(mapsArray, agentebpf.ShouldSecureMapsMapName, uint32(0), uint32(1))
	}
	if config.Flags.BlockPtrace {
		mapsArray = addToArray(mapsArray, agentebpf.BlockPtraceMapName, uint32(0), uint32(1))
	}
	if config.Flags.BlockInMemoryExec {
		mapsArray = addToArray(mapsArray, agentebpf.BlockInMemoryExecMapName, uint32(0), uint32(1))
	}
	if config.Flags.RestrictGPU {
		mapsArray = addToArray(mapsArray, agentebpf.RestrictGPUMapName, uint32(0), uint32(1))
	}
	if config.Flags.RestrictLDEnv {
		mapsArray = addToArray(mapsArray, agentebpf.ShouldStopLDEnvMapName, uint32(0), uint32(1))
	}
	if !config.Flags.DisableBPFOps {
		mapsArray = addToArray(mapsArray, agentebpf.RestrictBPFOpsMapName, uint32(0), uint32(1))
	}
	if config.ShutdownConfig.Port != "" && config.ShutdownConfig.PublicKey != "" {
		mapsArray = addToArray(mapsArray, agentebpf.ShouldStopShutdownMapName, uint32(0), uint32(1))
	}
	if config.Flags.EnableOpenat {
		mapsArray = addToArray(mapsArray, agentebpf.ShouldOutputOpenatsMapName, uint32(0), uint32(1))
	}

	userspacePid := uint32(os.Getpid())
	mapsArray = addToArray(mapsArray, agentebpf.UserspaceProcessPIDMapName, userspacePid, uint32(1))

	bootIDBytes, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, fmt.Errorf("failed to read boot ID: %w", err)
	}

	bootIDCharArray := [41]byte{}
	copy(bootIDCharArray[:], bootIDBytes)
	mapsArray = addToArray(mapsArray, agentebpf.BootIDMapName, uint32(0), bootIDCharArray)

	return mapsArray, nil
}

func pathKeyFromString(path string, containerPolicyMapper *PolicyIDMapper) (PathKey, PathKey, error) {
	parsedPath, err := pathParser(path)
	if err != nil {
		return PathKey{}, PathKey{}, fmt.Errorf("invalid path %q: %w", path, err)
	}

	containerPolicyID := containerPolicyMapper.GetOrAssign(parsedPath.ContainerPath)

	fullPath := strings.TrimSpace(parsedPath.FilePath)

	fullPathWithoutSlash := strings.TrimRight(fullPath, string(os.PathSeparator))
	if fullPathWithoutSlash == "" {
		return PathKey{}, PathKey{}, fmt.Errorf("path is empty")
	}

	fullPathWithSlash := fullPathWithoutSlash + string(os.PathSeparator)
	if len(fullPathWithSlash) > agentebpf.INPUT_PATH_MAX {
		return PathKey{}, PathKey{}, fmt.Errorf("path %q is too long, expected up to %d characters", fullPathWithSlash, agentebpf.INPUT_PATH_MAX)
	}

	dirPathWithSlash := [agentebpf.INPUT_PATH_MAX]byte{}
	copy(dirPathWithSlash[:], fullPathWithSlash)
	dirPathWithoutSlash := [agentebpf.INPUT_PATH_MAX]byte{}
	copy(dirPathWithoutSlash[:], fullPathWithoutSlash)

	return PathKey{PolicyID: containerPolicyID, DirectoryPath: dirPathWithSlash}, PathKey{PolicyID: containerPolicyID, DirectoryPath: dirPathWithoutSlash}, nil
}

type resolvedTCPDestination struct {
	DstIPv4 uint32
	DstPort uint16
}

func normalizeAllowedIPv4TCPDestination(raw string) ([]resolvedTCPDestination, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("destination is empty")
	}

	var host, portStr string
	hasPort := false
	if strings.Contains(raw, ":") {
		var err error
		host, portStr, err = net.SplitHostPort(raw)
		if err != nil {
			return nil, fmt.Errorf("must be in ip, ip:port, hostname, or hostname:port format: %w", err)
		}
		hasPort = true
	} else {
		host = raw
		portStr = "0"
	}

	port64, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || (hasPort && port64 == 0) {
		return nil, fmt.Errorf("must use a valid TCP port (1-65535)")
	}
	port := uint16(port64)

	if addr, err := netip.ParseAddr(host); err == nil && addr.Is4() {
		v4 := addr.As4()
		return []resolvedTCPDestination{{
			DstIPv4: binary.BigEndian.Uint32(v4[:]),
			DstPort: port,
		}}, nil
	}

	lookupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(lookupCtx, "ip4", host)
	if err != nil {
		return nil, fmt.Errorf("dns lookup failed for %q: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("dns lookup returned no IPv4 addresses for %q", host)
	}

	seen := make(map[uint32]bool, len(ips))
	out := make([]resolvedTCPDestination, 0, len(ips))
	for _, ip := range ips {
		ip = ip.Unmap()
		if !ip.Is4() {
			continue
		}
		v4 := ip.As4()
		dstIPv4 := binary.BigEndian.Uint32(v4[:])
		if seen[dstIPv4] {
			continue
		}
		seen[dstIPv4] = true
		out = append(out, resolvedTCPDestination{DstIPv4: dstIPv4, DstPort: port})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("dns lookup returned no valid IPv4 addresses for %q", host)
	}
	return out, nil
}

func makePathKey(policyID uint32, path string) (PathKey, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return PathKey{}, fmt.Errorf("path is empty")
	}
	if len(path) > agentebpf.INPUT_PATH_MAX {
		return PathKey{}, fmt.Errorf("path %q is too long, expected up to %d characters", path, agentebpf.INPUT_PATH_MAX)
	}

	pathBytes := [agentebpf.INPUT_PATH_MAX]byte{}
	copy(pathBytes[:], path)

	return PathKey{PolicyID: policyID, DirectoryPath: pathBytes}, nil
}

func parseDirs(dirs []string, policyID uint32, dirIDMapper *PolicyIDMapper, accessControl AccessControlValue) (AccessControlValue, error) {
	for _, dir := range dirs {
		parts := strings.Split(dir, ":")
		if len(parts) != 2 {
			return AccessControlValue{}, fmt.Errorf("invalid directory %q, expected format path:permission", dir)
		}
		rawPath := strings.TrimSpace(parts[0])
		permission := strings.TrimSpace(parts[1])
		if permission != "read" && permission != "write" {
			return AccessControlValue{}, fmt.Errorf("invalid permission %q, expected read or write", permission)
		}

		pathKeyWithoutSlash, err := makePathKey(policyID, strings.TrimRight(rawPath, string(os.PathSeparator)))
		if err != nil {
			return AccessControlValue{}, fmt.Errorf("invalid directory path %q: %w", rawPath, err)
		}
		pathKeyWithSlash, err := makePathKey(policyID, strings.TrimRight(rawPath, string(os.PathSeparator))+string(os.PathSeparator))
		if err != nil {
			return AccessControlValue{}, fmt.Errorf("invalid directory path %q: %w", rawPath, err)
		}

		id := dirIDMapper.GetOrAssign(pathKeyWithoutSlash)
		idWithSlash := dirIDMapper.GetOrAssign(pathKeyWithSlash)

		switch permission {
		case "read":
			if err := setIDBit(&accessControl.Read, id); err != nil {
				return AccessControlValue{}, fmt.Errorf("failed to set read bit for directory %q: %w", rawPath, err)
			}
			if err := setIDBit(&accessControl.Read, idWithSlash); err != nil {
				return AccessControlValue{}, fmt.Errorf("failed to set read bit for directory %q: %w", rawPath, err)
			}
		case "write":
			if err := setIDBit(&accessControl.Write, id); err != nil {
				return AccessControlValue{}, fmt.Errorf("failed to set write bit for directory %q: %w", rawPath, err)
			}
			if err := setIDBit(&accessControl.Write, idWithSlash); err != nil {
				return AccessControlValue{}, fmt.Errorf("failed to set write bit for directory %q: %w", rawPath, err)
			}
		}
	}
	return accessControl, nil
}

func parseExecutables(executables []string, policyID uint32, executableIDMapper *PolicyIDMapper, accessControl AccessControlValue) (AccessControlValue, error) {
	for _, executable := range executables {
		pathKeyWithoutSlash, err := makePathKey(policyID, executable)
		if err != nil {
			return AccessControlValue{}, fmt.Errorf("invalid executable path %q: %w", executable, err)
		}
		pathKeyWithSlash, err := makePathKey(policyID, executable+string(os.PathSeparator))
		if err != nil {
			return AccessControlValue{}, fmt.Errorf("invalid executable path %q: %w", executable, err)
		}
		id := executableIDMapper.GetOrAssign(pathKeyWithoutSlash)
		idWithSlash := executableIDMapper.GetOrAssign(pathKeyWithSlash)
		if err := setIDBit(&accessControl.Execute, id); err != nil {
			return AccessControlValue{}, fmt.Errorf("failed to set execute bit for executable %q: %w", executable, err)
		}
		if err := setIDBit(&accessControl.Execute, idWithSlash); err != nil {
			return AccessControlValue{}, fmt.Errorf("failed to set execute bit for executable %q: %w", executable, err)
		}
	}
	return accessControl, nil
}

func parseExclusiveIPs(ips []string, containerPolicyID uint32, networkIDMapper *PolicyIDMapper, exclusiveIPMask map[uint32]BitmaskArray, accessControl AccessControlValue, networkToConvert map[NetworkToConvert]bool) (AccessControlValue, error) {
	for _, ip := range ips {
		id := networkIDMapper.GetOrAssign(strings.TrimSpace(ip))
		if err := setIDBit(&accessControl.IPExclusiveOwner, id); err != nil {
			return AccessControlValue{}, fmt.Errorf("failed to set ip exclusive owner bit for IP %q: %w", ip, err)
		}
		mask := exclusiveIPMask[containerPolicyID]
		if err := setIDBit(&mask, id); err != nil {
			return AccessControlValue{}, fmt.Errorf("failed to set ip exclusive owner bit for IP %q: %w", ip, err)
		}
		exclusiveIPMask[containerPolicyID] = mask
		networkToConvert[NetworkToConvert{policyID: containerPolicyID, networkConnection: strings.TrimSpace(ip)}] = true
	}
	return accessControl, nil
}

func parseIPs(ips []string, networkIDMapper *PolicyIDMapper, accessControl AccessControlValue, networkToConvert map[NetworkToConvert]bool, containerPolicyID uint32) (AccessControlValue, error) {
	for _, ip := range ips {
		id := networkIDMapper.GetOrAssign(strings.TrimSpace(ip))
		if err := setIDBit(&accessControl.IPEgress, id); err != nil {
			return AccessControlValue{}, fmt.Errorf("failed to set ip egress bit for IP %q: %w", strings.TrimSpace(ip), err)
		}
		networkToConvert[NetworkToConvert{policyID: containerPolicyID, networkConnection: strings.TrimSpace(ip)}] = true
	}
	return accessControl, nil
}

// HasFsVerityDigests reports whether any policy in cfg has a fsverity_digest set.
func HasFsVerityDigests(cfg Config) bool {
	for _, p := range cfg.Policies {
		if p.FsVerityDigest != "" {
			return true
		}
	}
	return false
}

func ParseConfig(configPath string, debugEnabled bool) (Config, []agentebpf.EBPFMapWrite, map[string]uint32, *PolicyIDMapper, map[NetworkToConvert]bool, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return Config{}, nil, nil, nil, nil, fmt.Errorf("failed to read config file: %w", err)
	}

	config := Config{Flags: Flags{SecureMaps: true}}
	if err := yaml.Unmarshal(data, &config); err != nil { // the data should overlap the SecureMaps flag if it is set
		return Config{}, nil, nil, nil, nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	mapsArray, containerIDMapperMap, networkIDMapper, networkToConvert, err := parseConfigFromStruct(config, debugEnabled)
	if err != nil {
		return Config{}, nil, nil, nil, nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return config, mapsArray, containerIDMapperMap, networkIDMapper, networkToConvert, nil

}

func parseConfigFromStruct(config Config, debugEnabled bool) ([]agentebpf.EBPFMapWrite, map[string]uint32, *PolicyIDMapper, map[NetworkToConvert]bool, error) {
	if err := validateConfig(config); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to validate config: %w", err)
	}

	mapsArray, err := basicSetup(config, debugEnabled)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to basic setup: %w", err)
	}

	containerIDMapper := NewPolicyIDMapper()
	containerIDMapper.Set("", 0) // for host policy, policy_id 0

	dirIDMapper := NewPolicyIDMapper()
	executableIDMapper := NewPolicyIDMapper()
	networkIDMapper := NewPolicyIDMapper()
	exclusiveIPMask := make(map[uint32]BitmaskArray)

	networkToConvert := make(map[NetworkToConvert]bool)

	trustedExecutables := agentebpf.EBPFMapWrite{MapName: agentebpf.TrustedExecutablesMapName, Entries: make(map[any]any)}
	globalReadOnly := agentebpf.EBPFMapWrite{MapName: agentebpf.GlobalReadOnlyMapName, Entries: make(map[any]any)}
	fsverityPinlist := agentebpf.EBPFMapWrite{MapName: agentebpf.FsVerityPinlistMapName, Entries: make(map[any]any)}
	pythonIdentifiers := agentebpf.EBPFMapWrite{MapName: agentebpf.PythonIdentifierMapName, Entries: make(map[any]any)}

	for _, policy := range config.Policies {
		executable := policy.Executable
		if strings.TrimSpace(policy.Python) != "" {
			parsedPythonPolicy, err := pythonPolicyParser(policy.Python)
			if err != nil {
				return nil, nil, nil, nil, fmt.Errorf("invalid python policy %q: %w", policy.Python, err)
			}

			// if it is a python policy, the executable path is the python executable path
			executable = fmt.Sprintf("filepath = %s | container = %s", parsedPythonPolicy.FilePath, parsedPythonPolicy.ContainerPath)
			for _, lib := range parsedPythonPolicy.Libs {
				libs := fmt.Sprintf("type = filepath | filepath = %s | container = %s", lib, parsedPythonPolicy.ContainerPath)
				libsKeyWithSlash, libsKeyWithoutSlash, err := pathKeyFromString(libs, containerIDMapper)
				if err != nil {
					return nil, nil, nil, nil, fmt.Errorf("failed to get path key for python libs %q: %w", lib, err)
				}
				globalReadOnly.Entries[libsKeyWithSlash] = uint32(1)
				globalReadOnly.Entries[libsKeyWithoutSlash] = uint32(1)
			}
		}

		pathKeyWithSlash, pathKeyWithoutSlash, err := pathKeyFromString(executable, containerIDMapper)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to get path key for policy executable %q: %w", executable, err)
		}

		var accessControl AccessControlValue

		accessControl, err = parseDirs(policy.Directories, pathKeyWithSlash.PolicyID, dirIDMapper, accessControl)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to parse directories for policy %q: %w", executable, err)
		}
		accessControl, err = parseExecutables(policy.AllowedExecutables, pathKeyWithSlash.PolicyID, executableIDMapper, accessControl)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to parse executables for policy %q: %w", executable, err)
		}
		accessControl, err = parseExclusiveIPs(policy.IsAllowedToAccessIP, pathKeyWithSlash.PolicyID, networkIDMapper, exclusiveIPMask, accessControl, networkToConvert)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to parse IPs for policy %q: %w", executable, err)
		}

		if strings.TrimSpace(policy.Python) != "" && len(policy.PythonArgvExact) > 0 {
			encodedPythonArgs, err := pythonArgvExactParser(policy.PythonArgvExact)
			if err != nil {
				return nil, nil, nil, nil, fmt.Errorf("failed to build python identifier for policy %q: %w", executable, err)
			}
			encodedPythonCwd, err := pythonCwdParser(policy.PythonCwd)
			if err != nil {
				return nil, nil, nil, nil, fmt.Errorf("failed to build python cwd for policy %q: %w", executable, err)
			}
			if encodedPythonArgs != nil {
				pythonIdentifierKey := struct {
					Executable PathKey
					Cwd        [agentebpf.INPUT_PATH_MAX]byte
					Argv       [agentebpf.MAX_ARGS][agentebpf.MAX_ARG_LEN]byte
				}{
					Executable: pathKeyWithoutSlash,
					Argv:       *encodedPythonArgs,
				}
				if encodedPythonCwd != nil {
					pythonIdentifierKey.Cwd = *encodedPythonCwd
				}
				pythonIdentifiers.Entries[pythonIdentifierKey] = accessControl
			}
			accessControl = AccessControlValue{}
		}

		trustedExecutables.Entries[pathKeyWithSlash] = accessControl
		trustedExecutables.Entries[pathKeyWithoutSlash] = accessControl

		if policy.FsVerityDigest != "" {
			digestVal, err := parseFsVerityDigest(policy.FsVerityDigest)
			if err != nil {
				return nil, nil, nil, nil, fmt.Errorf("invalid fsverity_digest on policy %q: %w", executable, err)
			}
			fsverityPinlist.Entries[pathKeyWithSlash] = digestVal
			fsverityPinlist.Entries[pathKeyWithoutSlash] = digestVal
		}
	}

	allowedPtraceExecutables := agentebpf.EBPFMapWrite{MapName: agentebpf.AllowedPtraceExecutablesMapName, Entries: make(map[any]any)}
	ldEnvAllowedExecutables := agentebpf.EBPFMapWrite{MapName: agentebpf.LDEnvAllowedExecutablesMapName, Entries: make(map[any]any)}

	for _, attribute := range config.Attributes {
		parsedPath, err := pathParser(attribute.Path)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to parse attribute path %q: %w", attribute.Path, err)
		}
		pathKeyWithSlash, pathKeyWithoutSlash, err := pathKeyFromString(attribute.Path, containerIDMapper)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to get path key for attribute path %q: %w", attribute.Path, err)
		}

		switch parsedPath.Type {
		case "executable":
			var accessControl AccessControlValue
			accessControl, ok := trustedExecutables.Entries[pathKeyWithSlash].(AccessControlValue)
			if !ok {
				return nil, nil, nil, nil, fmt.Errorf("failed to get access control value for path key %v", pathKeyWithSlash)
			}
			if attribute.AllowedGPU {
				accessControl.GPU = 1

			}
			if attribute.AllowedPtrace {
				allowedPtraceExecutables.Entries[pathKeyWithSlash] = uint32(1)
				allowedPtraceExecutables.Entries[pathKeyWithoutSlash] = uint32(1)
			}
			if attribute.AllowedLDEnv {
				ldEnvAllowedExecutables.Entries[pathKeyWithSlash] = uint32(1)
				ldEnvAllowedExecutables.Entries[pathKeyWithoutSlash] = uint32(1)
			}
			if len(attribute.CanOnlyAccessIPs) > 0 {
				accessControl, err = parseIPs(attribute.CanOnlyAccessIPs, networkIDMapper, accessControl, networkToConvert, pathKeyWithSlash.PolicyID)
				if err != nil {
					return nil, nil, nil, nil, fmt.Errorf("failed to parse exclusive IPs for attribute %q: %w", attribute.Path, err)
				}
			}
			if attribute.OutputOpenats {
				accessControl.OutputOpenats = 1
			}
			trustedExecutables.Entries[pathKeyWithSlash] = accessControl
			trustedExecutables.Entries[pathKeyWithoutSlash] = accessControl

		case "filepath":
			if attribute.GlobalReadOnly {
				globalReadOnly.Entries[pathKeyWithSlash] = uint32(1)
				globalReadOnly.Entries[pathKeyWithoutSlash] = uint32(1)
			}
		default:
			return nil, nil, nil, nil, fmt.Errorf("invalid attribute type %q", parsedPath.Type)
		}
	}

	mapsArray = append(mapsArray, trustedExecutables, allowedPtraceExecutables, ldEnvAllowedExecutables, globalReadOnly, fsverityPinlist, pythonIdentifiers)
	ipToIDMap, err := setupIPtoIDMap(networkIDMapper, networkToConvert)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to setup ip to id map: %w", err)
	}
	mapsArray = append(mapsArray, ipToIDMap)
	if len(exclusiveIPMask) > 0 {
		entries := make(map[any]any, len(exclusiveIPMask))
		for policyID, mask := range exclusiveIPMask {
			entries[policyID] = mask
		}
		mapsArray = append(mapsArray, agentebpf.EBPFMapWrite{MapName: agentebpf.ExclusiveIPMaskMapName, Entries: entries})
	}

	mapsArray = append(mapsArray, executableIDMapper.ToMapList(agentebpf.ExecutableToIDMapName))
	mapsArray = append(mapsArray, dirIDMapper.ToMapList(agentebpf.DirToIDMapName))

	containerIDMapperMap := make(map[string]uint32)
	for key, value := range containerIDMapper.pathToID {
		containerIDMapperMap[key.(string)] = value
	}

	return mapsArray, containerIDMapperMap, networkIDMapper, networkToConvert, nil
}

func setupIPtoIDMap(networkIDMapper *PolicyIDMapper, networkToConvert map[NetworkToConvert]bool) (agentebpf.EBPFMapWrite, error) {
	ipToIDMap := agentebpf.EBPFMapWrite{MapName: agentebpf.IPToIDMapName, Entries: make(map[any]any)}
	for key := range networkToConvert {
		destinations, err := normalizeAllowedIPv4TCPDestination(key.networkConnection)
		if err != nil {
			return agentebpf.EBPFMapWrite{}, fmt.Errorf("failed to normalize allowed tcp destination: %w", err)
		}
		id := networkIDMapper.GetOrAssign(key.networkConnection)
		for _, destination := range destinations {
			ipToIDMap.Entries[IPToIDKey{PolicyID: key.policyID, DstIPv4: destination.DstIPv4, DstPort: destination.DstPort, Pad: 0}] = id
		}
	}
	return ipToIDMap, nil
}

func RefreshDNSPolicy(ctx context.Context, logger *slog.Logger, coll *cebpf.Collection, networkIDMapper *PolicyIDMapper, networkToConvert map[NetworkToConvert]bool) {
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				ipToIDMap, err := setupIPtoIDMap(networkIDMapper, networkToConvert)
				if err != nil {
					logger.Error("failed to setup ip to id map", "error", err)
				} else if err := agentebpf.ReplaceMapEntries[IPToIDKey, uint32](coll, agentebpf.IPToIDMapName, ipToIDMap.Entries); err != nil {
					logger.Error("failed to replace ip to id map", "error", err)
				}
			}
		}
	}()
}
