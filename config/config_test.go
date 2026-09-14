package config

import (
	"encoding/binary"
	"strings"
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

func TestAddToChunkEntriesUpdatesOnlyExactChunkKey(t *testing.T) {
	firstChunkA := "/" + strings.Repeat("a", agentebpf.FILE_CHUNK_SIZE-1)
	firstChunkB := "/" + strings.Repeat("b", agentebpf.FILE_CHUNK_SIZE-1)
	secondChunk := "s" + strings.Repeat("c", agentebpf.FILE_CHUNK_SIZE-1)
	shortPrefix := firstChunkA + secondChunk[:1]
	intendedPath := firstChunkA + secondChunk + "/tail"
	unrelatedPath := firstChunkB + secondChunk + "/tail"

	pathKey1 := testPathKey(7, shortPrefix)
	pathKey2 := testPathKey(7, intendedPath)
	pathKey3 := testPathKey(7, unrelatedPath)

	chunkIDMapper := NewRandomIDMapper()
	_, path2Entries, err := buildRestrictedPathKeys(pathKey2, chunkIDMapper)
	if err != nil {
		t.Fatalf("buildRestrictedPathKeys(pathKey2): %v", err)
	}
	_, path3Entries, err := buildRestrictedPathKeys(pathKey3, chunkIDMapper)
	if err != nil {
		t.Fatalf("buildRestrictedPathKeys(pathKey3): %v", err)
	}

	chunkEntries := make(map[any]any)
	for key, value := range path2Entries {
		chunkEntries[key] = value
	}
	for key, value := range path3Entries {
		chunkEntries[key] = value
	}

	path2SecondChunkKey := requireNonRootChunkKey(t, path2Entries)
	path3SecondChunkKey := requireNonRootChunkKey(t, path3Entries)

	updated, err := addToChunkEntries(chunkEntries, nil, 42, pathKey1, pathKey2)
	if err != nil {
		t.Fatalf("addToChunkEntries: %v", err)
	}

	intendedChunk, ok := updated[path2SecondChunkKey].(chunk)
	if !ok {
		t.Fatalf("missing intended second chunk entry")
	}
	if intendedChunk.matchingAccessIndex != 42 {
		t.Fatalf("intended chunk matchingAccessIndex = %d, want 42", intendedChunk.matchingAccessIndex)
	}

	unrelatedChunk, ok := updated[path3SecondChunkKey].(chunk)
	if !ok {
		t.Fatalf("missing unrelated second chunk entry")
	}
	if unrelatedChunk.matchingAccessIndex != agentebpf.INVALID_ACCESS_INDEX {
		t.Fatalf("unrelated chunk matchingAccessIndex = %d, want %d", unrelatedChunk.matchingAccessIndex, agentebpf.INVALID_ACCESS_INDEX)
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

func testPathKey(policyID uint32, path string) PathKey {
	var directoryPath [agentebpf.INPUT_PATH_MAX]byte
	copy(directoryPath[:], path)
	return PathKey{PolicyID: policyID, DirectoryPath: directoryPath}
}

func requireNonRootChunkKey(t *testing.T, entries map[chunkToIDKey]chunk) chunkToIDKey {
	t.Helper()
	for key := range entries {
		if binary.NativeEndian.Uint32(key[4:8]) != 0 {
			return key
		}
	}
	t.Fatalf("missing non-root chunk key")
	return chunkToIDKey{}
}
