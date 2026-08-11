package ebpf

import (
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
)

func TestCheckPrerequisites(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to probe LSM prerequisites")
	}

	err := checkPrerequisites()
	if err != nil {
		t.Fatalf("checkPrerequisites() failed: %v", err)
	}
}

func TestParseLSMKernelArg(t *testing.T) {
	tests := []struct {
		name       string
		cmdline    string
		wantHasLSM bool
		wantHasBPF bool
	}{
		{
			name:       "no lsm arg",
			cmdline:    "BOOT_IMAGE=/vmlinuz root=/dev/sda1 ro quiet",
			wantHasLSM: false,
			wantHasBPF: false,
		},
		{
			name:       "lsm arg with bpf",
			cmdline:    "root=/dev/sda1 ro lsm=lockdown,yama,apparmor,bpf",
			wantHasLSM: true,
			wantHasBPF: true,
		},
		{
			name:       "lsm arg without bpf",
			cmdline:    "root=/dev/sda1 ro lsm=lockdown,yama,apparmor",
			wantHasLSM: true,
			wantHasBPF: false,
		},
		{
			name:       "token contains lsm substring but not argument",
			cmdline:    "root=/dev/sda1 ro mylsmflag=1",
			wantHasLSM: false,
			wantHasBPF: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHasLSM, gotHasBPF := parseLSMKernelArg(tt.cmdline)
			if gotHasLSM != tt.wantHasLSM {
				t.Fatalf("parseLSMKernelArg() hasLSMArg = %v, want %v", gotHasLSM, tt.wantHasLSM)
			}
			if gotHasBPF != tt.wantHasBPF {
				t.Fatalf("parseLSMKernelArg() hasBPFModule = %v, want %v", gotHasBPF, tt.wantHasBPF)
			}
		})
	}
}

func TestIsRebootRequiredFromLSMArg(t *testing.T) {
	tests := []struct {
		name       string
		cmdline    string
		wantReboot bool
	}{
		{
			name:       "no lsm arg means no reboot required",
			cmdline:    "BOOT_IMAGE=/vmlinuz root=/dev/sda1 ro quiet",
			wantReboot: false,
		},
		{
			name:       "bpf present in lsm means no reboot required",
			cmdline:    "root=/dev/sda1 ro lsm=lockdown,yama,apparmor,bpf",
			wantReboot: false,
		},
		{
			name:       "lsm without bpf means reboot required",
			cmdline:    "root=/dev/sda1 ro lsm=lockdown,yama,apparmor",
			wantReboot: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasLSMArg, hasBPFModule := parseLSMKernelArg(tt.cmdline)
			gotReboot := hasLSMArg && !hasBPFModule
			if gotReboot != tt.wantReboot {
				t.Fatalf("reboot decision = %v, want %v", gotReboot, tt.wantReboot)
			}
		})
	}
}

func TestSelectBPFProgram(t *testing.T) {
	tests := []struct {
		name          string
		kernel615Plus bool
		disableBPFOps bool
		wantProgram   string
		wantEnabled   bool
	}{
		{
			name:          "disabled bpf ops",
			kernel615Plus: true,
			disableBPFOps: true,
			wantProgram:   "",
			wantEnabled:   false,
		},
		{
			name:          "kernel 6.15+ uses lsm_bpf",
			kernel615Plus: true,
			disableBPFOps: false,
			wantProgram:   LSMBPFProgramName,
			wantEnabled:   true,
		},
		{
			name:          "kernel below 6.15 uses compat",
			kernel615Plus: false,
			disableBPFOps: false,
			wantProgram:   LSMBPFCompatName,
			wantEnabled:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotProgram, gotEnabled := selectBPFProgram(tt.kernel615Plus, tt.disableBPFOps)
			if gotProgram != tt.wantProgram || gotEnabled != tt.wantEnabled {
				t.Fatalf("selectBPFProgram(%v, %v) = (%q, %v), want (%q, %v)",
					tt.kernel615Plus, tt.disableBPFOps, gotProgram, gotEnabled, tt.wantProgram, tt.wantEnabled)
			}
		})
	}
}

func TestPruneBPFPrograms(t *testing.T) {
	tests := []struct {
		name          string
		kernel615Plus bool
		disableBPFOps bool
		wantLSMBPF    bool
		wantCompat    bool
	}{
		{
			name:          "disabled bpf ops removes both programs",
			kernel615Plus: true,
			disableBPFOps: true,
			wantLSMBPF:    false,
			wantCompat:    false,
		},
		{
			name:          "kernel 6.15+ keeps only lsm_bpf",
			kernel615Plus: true,
			disableBPFOps: false,
			wantLSMBPF:    true,
			wantCompat:    false,
		},
		{
			name:          "kernel below 6.15 keeps only compat",
			kernel615Plus: false,
			disableBPFOps: false,
			wantLSMBPF:    false,
			wantCompat:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := &ebpf.CollectionSpec{
				Programs: map[string]*ebpf.ProgramSpec{
					LSMBPFProgramName: nil,
					LSMBPFCompatName:  nil,
					"unrelated_prog":  nil,
				},
			}

			pruneBPFPrograms(spec, tt.kernel615Plus, tt.disableBPFOps)

			_, gotLSMBPF := spec.Programs[LSMBPFProgramName]
			_, gotCompat := spec.Programs[LSMBPFCompatName]
			_, gotUnrelated := spec.Programs["unrelated_prog"]

			if gotLSMBPF != tt.wantLSMBPF || gotCompat != tt.wantCompat {
				t.Fatalf("pruneBPFPrograms(%v, %v) kept (lsm_bpf=%v, compat=%v), want (lsm_bpf=%v, compat=%v)",
					tt.kernel615Plus, tt.disableBPFOps, gotLSMBPF, gotCompat, tt.wantLSMBPF, tt.wantCompat)
			}
			if !gotUnrelated {
				t.Fatalf("pruneBPFPrograms removed unrelated program unexpectedly")
			}
		})
	}
}

func TestReplaceMapEntriesRemapsKeys(t *testing.T) {
	testMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 32,
	})
	if err != nil {
		t.Skipf("skipping: failed to create eBPF test map: %v", err)
	}
	defer testMap.Close()

	coll := &ebpf.Collection{
		Maps: map[string]*ebpf.Map{
			"test_map": testMap,
		},
	}

	if err := testMap.Update(uint32(1), uint32(10), ebpf.UpdateAny); err != nil {
		t.Fatalf("failed to seed key 1: %v", err)
	}
	if err := testMap.Update(uint32(2), uint32(20), ebpf.UpdateAny); err != nil {
		t.Fatalf("failed to seed key 2: %v", err)
	}

	replacementEntries := map[any]any{
		uint32(2): uint32(200),
		uint32(3): uint32(300),
	}
	if err := ReplaceMapEntries[uint32, uint32](coll, "test_map", replacementEntries); err != nil {
		t.Fatalf("ReplaceMapEntries() failed: %v", err)
	}

	var value uint32
	err = testMap.Lookup(uint32(1), &value)
	if !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("expected key 1 to be removed, got err=%v value=%d", err, value)
	}

	if err := testMap.Lookup(uint32(2), &value); err != nil {
		t.Fatalf("expected key 2 to exist: %v", err)
	}
	if value != 200 {
		t.Fatalf("expected key 2 value 200, got %d", value)
	}

	if err := testMap.Lookup(uint32(3), &value); err != nil {
		t.Fatalf("expected key 3 to exist: %v", err)
	}
	if value != 300 {
		t.Fatalf("expected key 3 value 300, got %d", value)
	}
}
