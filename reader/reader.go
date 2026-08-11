package reader

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/bomfather/bomfather/agent/cri"
	"github.com/bomfather/bomfather/agent/ebpf"
	"github.com/bomfather/bomfather/agent/proto"
)

var (
	bootTimeOnce   sync.Once
	cachedBootTime time.Time
	cachedBootErr  error
)

// ----------------- Data structures from ebpf outputs -----------------

type ContainerID struct {
	CgroupID                         uint64
	ContainerCorrelationCounterIndex uint64
	Timestamp                        uint64
}

type ProcessID struct {
	TGID        uint32
	_           [4]byte // pad to align StartTime to 8
	StartTime   uint64
	ContainerID ContainerID
	BootID      [ebpf.BOOT_ID_MAX]byte
	_           [7]byte // tail pad to 80
}

type ExecveEvent struct {
	Comm    [ebpf.TASK_COMM_LEN]byte
	Exepath [ebpf.INPUT_PATH_MAX]byte
	Process ProcessID
	Parent  ProcessID
	Argv    [ebpf.MAX_ARGS][ebpf.MAX_ARG_LEN]byte
	Envp    [ebpf.MAX_ARGS][ebpf.MAX_ARG_LEN]byte
}

type ViolationEvent struct {
	Process   ProcessID
	Timestamp uint64
	Type      uint32
	Filename  [ebpf.INPUT_PATH_MAX]byte
	Exepath   [ebpf.INPUT_PATH_MAX]byte
	_         [4]byte // tail pad to 2144
}

type OpenatEvent struct {
	Process  ProcessID
	Filename [ebpf.INPUT_PATH_MAX]byte
	OpenMode uint32
	Exepath  [ebpf.INPUT_PATH_MAX]byte
	_        [4]byte // tail pad to 1112
}

type EventStreams struct {
	OpenatStream    chan *proto.OpenatEventWrapper
	ExecveStream    chan *proto.ExecveEventWrapper
	ViolationStream chan *proto.ViolationEventWrapper
}

func ByteArrayToString(b []byte) string {
	start := 0
	for start < len(b) && b[start] == 0 {
		start++
	}

	end := start
	for end < len(b) && b[end] != 0 {
		end++
	}

	if !utf8.Valid(b[start:end]) {
		return ""
	}

	return string(b[start:end])
}

func ProcessIDToProto(process ProcessID) *proto.ProcessID {
	return &proto.ProcessID{
		Tgid:      process.TGID,
		StartTime: unixTimstamptoUTC(process.StartTime),
		Container: &proto.ContainerID{
			CgroupId:  process.ContainerID.CgroupID,
			Timestamp: unixTimstamptoUTC(process.ContainerID.Timestamp),
		},
		BootId: ByteArrayToString(process.BootID[:]),
	}
}

func ReadOpenatEvent(ctx context.Context, logger *slog.Logger, record []byte, nodeId uint64, cgroupToContainerPathMap *cri.ContainerMaps) (proto.OpenatEventWrapper, error) {
	var event OpenatEvent
	if err := binary.Read(bytes.NewBuffer(record), binary.LittleEndian, &event); err != nil {
		logger.Error("Failed to read openat event", "error", err)
		return proto.OpenatEventWrapper{}, err
	}
	return proto.OpenatEventWrapper{
		NodeId:        nodeId,
		ContainerPath: cgroupToContainerPathMap.Lookup(event.Process.ContainerID.ContainerCorrelationCounterIndex),
		Event: &proto.OpenatEvent{
			Filename: ByteArrayToString(event.Filename[:]),
			OpenMode: event.OpenMode,
			Exepath:  ByteArrayToString(event.Exepath[:]),
			Process:  ProcessIDToProto(event.Process),
		},
	}, nil
}

func ReadExecveEvent(ctx context.Context, logger *slog.Logger, record []byte, nodeId uint64, cgroupToContainerPathMap *cri.ContainerMaps) (proto.ExecveEventWrapper, error) {
	var event ExecveEvent
	if err := binary.Read(bytes.NewBuffer(record), binary.LittleEndian, &event); err != nil {
		logger.Error("Failed to read execve event", "error", err)
		return proto.ExecveEventWrapper{}, errors.New("failed to read execve event")
	}

	var argv []string
	for _, arg := range event.Argv {
		argv = append(argv, ByteArrayToString(arg[:]))
	}
	var envp []string
	for _, env := range event.Envp {
		envp = append(envp, ByteArrayToString(env[:]))
	}
	return proto.ExecveEventWrapper{
		NodeId:        nodeId,
		ContainerPath: cgroupToContainerPathMap.Lookup(event.Process.ContainerID.ContainerCorrelationCounterIndex),
		Event: &proto.ExecveEvent{
			Comm:    ByteArrayToString(event.Comm[:]),
			Exepath: ByteArrayToString(event.Exepath[:]),
			Process: ProcessIDToProto(event.Process),
			Parent:  ProcessIDToProto(event.Parent),
			Argv:    argv,
			Envp:    envp,
		},
	}, nil
}

func ReadViolationEvent(ctx context.Context, logger *slog.Logger, record []byte, nodeId uint64, cgroupToContainerPathMap *cri.ContainerMaps) (proto.ViolationEventWrapper, error) {
	var event ViolationEvent
	if err := binary.Read(bytes.NewBuffer(record), binary.LittleEndian, &event); err != nil {
		logger.Error("Failed to read violation event", "error", err)
		return proto.ViolationEventWrapper{}, err
	}
	return proto.ViolationEventWrapper{
		Path:          ByteArrayToString(event.Filename[:]),
		ContainerPath: cgroupToContainerPathMap.Lookup(event.Process.ContainerID.ContainerCorrelationCounterIndex),
		NodeId:        nodeId,
		Event: &proto.ViolationEvent{
			Process:   ProcessIDToProto(event.Process),
			Timestamp: unixTimstamptoUTC(event.Timestamp),
			Type:      event.Type,
			Filename:  ByteArrayToString(event.Filename[:]),
			Exepath:   ByteArrayToString(event.Exepath[:]),
		},
	}, nil
}

// our goal is to basically read the three event sources and then push the events to the appropriate channels. that is all this file should do.
func ReadEvents(ctx context.Context, logger *slog.Logger, source ebpf.EBPFResources, nodeId uint64, streams EventStreams, cgroupToContainerPathMap *cri.ContainerMaps) {
	sources := []ebpf.EBPFSource{
		source.OpenatSource,
		source.ExecveSource,
		source.ViolationSource,
	}

	var wg sync.WaitGroup
	wg.Add(len(sources))

	// Ensure blocking Read() calls are released during shutdown.
	go func() {
		<-ctx.Done()
		_ = source.OpenatSource.Close()
		_ = source.ExecveSource.Close()
		_ = source.ViolationSource.Close()
	}()

	for _, s := range sources {
		go func(s ebpf.EBPFSource) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					record, err := s.Read()
					if err != nil {
						if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, perf.ErrClosed) {
							return
						}
						if ctx.Err() != nil {
							return
						}
						logger.Error("Error reading event", "error", err)
						continue
					}
					switch s {
					case source.OpenatSource:
						evt, err := ReadOpenatEvent(ctx, logger, record, nodeId, cgroupToContainerPathMap)
						if err != nil {
							logger.Error("Failed to read openat event", "error", err)
							continue
						}
						select {
						case <-ctx.Done():
							return
						default:
							streams.OpenatStream <- &evt
						}
					case source.ExecveSource:
						evt, err := ReadExecveEvent(ctx, logger, record, nodeId, cgroupToContainerPathMap)
						if err != nil {
							logger.Error("Failed to read execve event", "error", err)
							continue
						}
						select {
						case <-ctx.Done():
							return
						default:
							streams.ExecveStream <- &evt
						}
					case source.ViolationSource:
						evt, err := ReadViolationEvent(ctx, logger, record, nodeId, cgroupToContainerPathMap)
						if err != nil {
							logger.Error("Failed to read violation event", "error", err)
							continue
						}
						select {
						case <-ctx.Done():
							return
						default:
							streams.ViolationStream <- &evt
						}
					default:
						logger.Error("Unknown event source", "source", s)
						continue
					}
				}
			}
		}(s)
	}
	wg.Wait()
}

func unixTimstamptoUTC(monotonicTimestamp uint64) uint64 {
	bootTimeOnce.Do(func() {
		cachedBootTime, cachedBootErr = bootTime()
	})
	if cachedBootErr != nil {
		return 0
	}
	bootUnixNano := cachedBootTime.UnixNano()
	if bootUnixNano < 0 {
		return 0
	}
	return uint64(bootUnixNano) + monotonicTimestamp
}

func bootTime() (time.Time, error) {
	var info syscall.Sysinfo_t
	if err := syscall.Sysinfo(&info); err != nil {
		return time.Time{}, err
	}
	uptime := time.Duration(info.Uptime) * time.Second
	return time.Now().UTC().Add(-uptime), nil
}
