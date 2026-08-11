//go:build linux

package cri

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/containerd/cgroups/v3"
)

func TestContainerMaps_StoresContainerStateInTwoMaps(t *testing.T) {
	m := NewContainerMaps()

	index := m.Store("ns:pod:container", "container-123")
	if got := m.Lookup(index); got != "ns:pod:container" {
		t.Fatalf("Lookup(%d) = %q, want %q", index, got, "ns:pod:container")
	}

	m.StoreCgroupID("container-123", 99)
	cgroupID, ok := m.LookupCgroupID("container-123")
	if !ok {
		t.Fatal("LookupCgroupID(container-123) = missing, want stored cgroup id")
	}
	if cgroupID != 99 {
		t.Fatalf("LookupCgroupID(container-123) = %d, want 99", cgroupID)
	}

	if len(m.containers) != 1 {
		t.Fatalf("containers size = %d, want 1", len(m.containers))
	}
	if len(m.pathByIndex) != 1 {
		t.Fatalf("pathByIndex size = %d, want 1", len(m.pathByIndex))
	}

	m.Delete("container-123")
	if got := m.Lookup(index); got != "" {
		t.Fatalf("Lookup(%d) after Delete = %q, want empty", index, got)
	}
	if _, ok := m.LookupCgroupID("container-123"); ok {
		t.Fatal("LookupCgroupID(container-123) after Delete = present, want missing")
	}
}

func TestContainerMaps_StoreAllocatesIndexAfterCgroupID(t *testing.T) {
	m := NewContainerMaps()

	m.StoreCgroupID("container-123", 99)

	index := m.Store("ns:pod:container", "container-123")
	if index == 0 {
		t.Fatal("Store returned correlation index 0, want non-zero index")
	}
	if got := m.Lookup(0); got != "" {
		t.Fatalf("Lookup(0) = %q, want empty", got)
	}
	if got := m.Lookup(index); got != "ns:pod:container" {
		t.Fatalf("Lookup(%d) = %q, want %q", index, got, "ns:pod:container")
	}

	cgroupID, ok := m.LookupCgroupID("container-123")
	if !ok {
		t.Fatal("LookupCgroupID(container-123) = missing, want stored cgroup id")
	}
	if cgroupID != 99 {
		t.Fatalf("LookupCgroupID(container-123) = %d, want 99", cgroupID)
	}
}

func TestGetCgroupIdFromPath_matchesCgroupDirInode(t *testing.T) {
	procCgroup := filepath.Join("/proc", strconv.Itoa(os.Getpid()), "cgroup")
	_, unified, err := cgroups.ParseCgroupFileUnified(procCgroup)
	if err != nil {
		t.Fatalf("parse %s: %v", procCgroup, err)
	}
	if unified == "" {
		t.Fatal("no unified cgroup path in proc")
	}

	relative := strings.TrimPrefix(unified, "/")
	full := filepath.Join("/sys/fs/cgroup", relative)
	st, err := os.Stat(full)
	if err != nil {
		t.Skipf("stat cgroup path %q: %v", full, err)
	}
	ino := st.Sys().(*syscall.Stat_t).Ino

	id, err := GetCgroupIdFromPath(relative)
	if err != nil {
		t.Fatalf("GetCgroupIdFromPath(%q): %v", relative, err)
	}
	if id != ino {
		t.Fatalf("GetCgroupIdFromPath = %d, want inode %d for %q", id, ino, relative)
	}
}

func TestGetCgroupIdFromPath_nonexistentPath(t *testing.T) {
	bogus := "bomfather-nonexistent-cgroup-test-8f3a2c1e"
	_, err := GetCgroupIdFromPath(bogus)
	if err == nil {
		t.Fatalf("GetCgroupIdFromPath(%q) succeeded, want error", bogus)
	}
}
func TestCgroupPathFromPID_matchesProcUnified(t *testing.T) {
	pid := os.Getpid()
	got, err := cgroupPathFromPID(pid)
	if err != nil {
		t.Fatalf("cgroupPathFromPID(%d): %v", pid, err)
	}

	proc := filepath.Join("/proc", strconv.Itoa(pid), "cgroup")
	_, unified, err := cgroups.ParseCgroupFileUnified(proc)
	if err != nil {
		t.Fatalf("parse %s: %v", proc, err)
	}
	want := strings.TrimPrefix(unified, "/")
	if got != want {
		t.Fatalf("cgroupPathFromPID = %q, want %q (from %s)", got, want, proc)
	}
}

func TestCgroupPathFromPID_nonexistentProcess(t *testing.T) {
	const fakePID = 999_999_999
	_, err := cgroupPathFromPID(fakePID)
	if err == nil {
		t.Fatalf("cgroupPathFromPID(%d) succeeded, want error", fakePID)
	}
}
