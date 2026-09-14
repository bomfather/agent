package integration

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bomfather/bomfather/agent/ebpf"
	"github.com/bomfather/bomfather/agent/integration/testdata/command"
)

const longPathMinLen = ebpf.FILE_CHUNK_SIZE*2 + 1

var chunkBoundaryLens = []int{
	ebpf.FILE_CHUNK_SIZE - 1,
	ebpf.FILE_CHUNK_SIZE,
	ebpf.FILE_CHUNK_SIZE + 1,
	ebpf.FILE_CHUNK_SIZE*2 - 1,
	ebpf.FILE_CHUNK_SIZE * 2,
	ebpf.FILE_CHUNK_SIZE*2 + 1,
}

func TestRestrictedDirLongPathIsEnforced(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test must be run as root")
	}
	guardedDir, secretFilepath := createLongDirectory(t, longPathMinLen)
	assertGrantedReadUnregisteredDenied(t, guardedDir, secretFilepath)
}

func TestRestrictedDirChunkBoundaries(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test must be run as root")
	}
	for _, pathLen := range chunkBoundaryLens {
		t.Run(fmt.Sprintf("len_%d", pathLen), func(t *testing.T) {
			guardedDir, secretFilepath := createLongDirectory(t, pathLen)
			assertGrantedReadUnregisteredDenied(t, guardedDir, secretFilepath)
		})
	}
}

func assertGrantedReadUnregisteredDenied(t *testing.T, guardedDir, secretFilepath string) {
	t.Helper()
	h := buildTestBinary(t)
	newtool := buildTestBinaryAt(t)
	runAgent(t, fmt.Sprintf(policyPrefix, h, guardedDir, h))

	assertCanRead(t, h, secretFilepath)

	assertReadDenied(t, newtool, secretFilepath, fmt.Sprintf("unregistered %s read guarded file but should be denied", newtool))
}

func TestRestrictedDirSharedPrefixSiblingIsIsolated(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test must be run as root")
	}
	dirA, fileA, dirB, fileB := createPrefixedSiblingDirs(t, longPathMinLen)
	h := buildTestBinary(t)
	runAgent(t, bootstrapPolicyReadAllowedAndRegisterSiblingDir(t, h, dirA, dirB, h))
	assertCanRead(t, h, fileA)
	assertReadDenied(t, h, fileB, "h read sibling dir; chunked path lookup aliased the grant")
}


func TestRestrictedDirShortPrefixSurvivesLongerSamePolicyPath(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test must be run as root")
	}

	h := buildTestBinary(t)
	shortDir, _ := createLongDirectory(t, ebpf.FILE_CHUNK_SIZE-1)

	// Deliberately avoid filepath.Join here. pathKeyFromString registers both
	// "path" and "path/", so using a child path would let the slash-suffixed
	// variant rescue the old lookup. We want the trace.c example shape:
	// short="/cha", long="/char/extra", query="/char/other".
	longDir := shortDir + "r-registered-branch"
	queryDir := shortDir + "r-query-branch"

	if err := os.MkdirAll(longDir, 0o755); err != nil {
		t.Fatalf("create longer allowed directory: %v", err)
	}
	queryFile := writeSecret(t, queryDir)

	policy := fmt.Sprintf(`
policies:
  - executable: "filepath = %s"
    can_access_dirs:
      - "%s: read"
      - "%s: read"
    can_run:
      - "%s"
`, h, shortDir, longDir, h)
	runAgent(t, policy)

	assertCanRead(t, h, queryFile)
}

func TestGlobalReadOnlyShortPrefixSurvivesLongerSameMapPath(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test must be run as root")
	}

	h := buildTestBinary(t)
	shortPrefix, _ := createLongDirectory(t, ebpf.FILE_CHUNK_SIZE-1)

	// Deliberately avoid filepath.Join so the shared next byte is not "/".
	// This models the trace.c example shape:
	// short="/cha", long="/char/extra", query="/char/other".
	longPath := shortPrefix + "r-registered"
	queryPath := shortPrefix + "r-query"
	if err := os.WriteFile(longPath, []byte("registered\n"), 0o644); err != nil {
		t.Fatalf("write longer protected path: %v", err)
	}
	if err := os.WriteFile(queryPath, []byte("original\n"), 0o644); err != nil {
		t.Fatalf("write queried path: %v", err)
	}

	runAgent(t, bootstrapPolicyGlobalReadOnly(t, shortPrefix, longPath))

	cmd := exec.Command(h, command.WriteToReadonly, "0", queryPath)
	var output bytes.Buffer
	cmd.Stdin = bytes.NewReader(nil)
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		t.Fatalf("write to %s should be blocked by the shorter protected prefix: %v\n%s", queryPath, err, output.String())
	}
}


func assertCanRead(t *testing.T, exe, path string) {
	t.Helper()
	if err := exec.Command(exe, command.Read, path).Run(); err != nil {
		t.Fatalf("%s should read %s: %v", exe, path, err)
	}
}

func assertReadDenied(t *testing.T, exe, path, failMsg string) {
	t.Helper()
	err := exec.Command(exe, command.ReadMustBeDenied, path).Run()
	if err == nil {
		return
	}
	if code := mustExitCode(t, err); code == 10 {
		t.Fatalf("%s", failMsg)
	}
	t.Fatalf("unexpected error: %v", err)
}

func createPrefixedSiblingDirs(t *testing.T, prefixLen int) (dirA, fileA, dirB, fileB string) {
	t.Helper()
	parent, _ := createLongDirectory(t, prefixLen)
	dirA = filepath.Join(parent, "allowed")
	dirB = filepath.Join(parent, "blocked")
	return dirA, writeSecret(t, dirA), dirB, writeSecret(t, dirB)
}

func createLongDirectory(t *testing.T, pathLen int) (dir, file string) {
	t.Helper()
	base := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(base); err == nil && resolved != "" {
		base = resolved
	} else {
		t.Fatalf("eval symlinks: %v, %s", err, base)
	}
	pad := pathLen - len(base) - 1
	if pad < 1 {
		t.Fatalf("temp dir %q is already %d bytes, want room for a %d-byte path", base, len(base), pathLen)
	}
	dir = filepath.Join(base, strings.Repeat("p", pad))
	if len(dir) != pathLen {
		t.Fatalf("long directory is %d bytes, want %d: %s", len(dir), pathLen, dir)
	}
	return dir, writeSecret(t, dir)
}

func writeSecret(t *testing.T, dir string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create directory: %v", err)
	}
	file := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(file, []byte("secret\n"), 0o644); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	return file
}
