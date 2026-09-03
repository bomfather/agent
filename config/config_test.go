package config

import (
	"testing"

	agentebpf "github.com/bomfather/bomfather/agent/ebpf"
)

func TestParseConfigFromStructIncludesAgentExecutable(t *testing.T) {
	exe, err := getExecutablePath()
	if err != nil {
		t.Fatalf("getExecutablePath: %v", err)
	}

	mapper := NewPolicyIDMapper()
	mapper.Set("", 0)
	withSlash, withoutSlash, err := pathKeyFromString("filepath = "+exe, mapper)
	if err != nil {
		t.Fatalf("pathKeyFromString: %v", err)
	}

	tests := []struct {
		name      string
		config    Config
		wantEmpty bool
	}{
		{
			name:      "empty policies still protect agent",
			config:    Config{},
			wantEmpty: true,
		},
		{
			name: "unrelated policy still protect agent",
			config: Config{
				Policies: []Policy{{
					Executable:  "filepath = /tmp/other-bin",
					Directories: []string{"/tmp: read"},
				}},
			},
			wantEmpty: true,
		},
		{
			name: "policy for agent path keeps access control",
			config: Config{
				Policies: []Policy{{
					Executable:  "filepath = " + exe,
					Directories: []string{"/tmp: read"},
				}},
			},
			wantEmpty: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mapsArray, _, _, _, err := parseConfigFromStruct(tt.config, false)
			if err != nil {
				t.Fatalf("parseConfigFromStruct: %v", err)
			}
			entries := trustedExecutableEntries(t, mapsArray)

			gotWith, ok := entries[withSlash].(AccessControlValue)
			if !ok {
				t.Fatalf("missing agent key with slash")
			}
			gotWithout, ok := entries[withoutSlash].(AccessControlValue)
			if !ok {
				t.Fatalf("missing agent key without slash")
			}

			empty := AccessControlValue{}
			if tt.wantEmpty {
				if gotWith != empty || gotWithout != empty {
					t.Fatalf("want empty access control, got %+v / %+v", gotWith, gotWithout)
				}
				return
			}
			if gotWith == empty || gotWithout == empty {
				t.Fatalf("want policy access control preserved, got empty")
			}
		})
	}
}

func trustedExecutableEntries(t *testing.T, mapsArray []agentebpf.EBPFMapWrite) map[any]any {
	t.Helper()
	for _, m := range mapsArray {
		if m.MapName == agentebpf.TrustedExecutablesMapName {
			return m.Entries
		}
	}
	t.Fatalf("trusted executables map missing")
	return nil
}
