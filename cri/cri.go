package cri

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/containerd/cgroups/v3"
	tasksvc "github.com/containerd/containerd/api/services/tasks/v1"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	runtimev1 "k8s.io/cri-api/pkg/apis/runtime/v1"

	ebpfhelper "github.com/bomfather/bomfather/agent/ebpf"
)

var ErrCgroupV2Required = errors.New("cgroup v2 required")

const containerdNamespaceHeader = "containerd-namespace"

type ContainerMaps struct {
	mu               sync.RWMutex
	pathByIndex      map[uint64]string         // correlation index to container path
	containers       map[string]containerState // container id (cri) to container state
	correlationIndex uint64                    // the current correlation index (will have to add 1 to this when a new container is created)
}

type containerState struct {
	index       uint64
	cgroupID    uint64
	hasCgroupID bool
}

type ContainerContext struct {
	PolicyID         uint32
	_                uint32
	CorrelationIndex uint64
}

func NewContainerMaps() *ContainerMaps {
	return &ContainerMaps{
		mu:               sync.RWMutex{},
		pathByIndex:      make(map[uint64]string),
		containers:       make(map[string]containerState),
		correlationIndex: 0,
	}
}

func (i *ContainerMaps) Lookup(correlationIndex uint64) string {
	if i == nil {
		return ""
	}

	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.pathByIndex[correlationIndex]
}

func (i *ContainerMaps) Store(containerPath string, containerID string) uint64 {
	if i == nil {
		return 0
	}
	i.mu.Lock()
	defer i.mu.Unlock()

	state, ok := i.containers[containerID]
	if !ok || state.index == 0 {
		i.correlationIndex++
		state.index = i.correlationIndex
	}

	i.pathByIndex[state.index] = containerPath
	i.containers[containerID] = state
	return state.index
}

func (i *ContainerMaps) Delete(containerID string) {
	if i == nil {
		return
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	state, ok := i.containers[containerID]
	if !ok {
		return
	}
	delete(i.containers, containerID)
	delete(i.pathByIndex, state.index)
}

func (i *ContainerMaps) StoreCgroupID(containerID string, cgroupID uint64) {
	if i == nil {
		return
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	state := i.containers[containerID]
	state.cgroupID = cgroupID
	state.hasCgroupID = true
	i.containers[containerID] = state
}

func (i *ContainerMaps) LookupCgroupID(containerID string) (uint64, bool) {
	if i == nil {
		return 0, false
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	state, ok := i.containers[containerID]
	if !ok || !state.hasCgroupID {
		return 0, false
	}
	return state.cgroupID, true
}

func UpdateEBPFContainerContext(ctx context.Context, logger *slog.Logger, containerIDMapperMap map[string]uint32, socketPath string, coll *ebpf.Collection) *ContainerMaps {
	if socketPath == "" {
		return nil
	}
	conn, err := grpc.NewClient("unix:"+socketPath, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil
	}

	containerMaps := NewContainerMaps()
	runtimeClient := runtimev1.NewRuntimeServiceClient(conn)
	taskClient := tasksvc.NewTasksClient(conn)
	stream, err := runtimeClient.GetContainerEvents(ctx, &runtimev1.GetEventsRequest{})
	if err != nil {
		conn.Close()
		return nil
	}

	logger.Info("watching CRI container create events", "socket", socketPath)

	// first get all the current running containers
	ticker := time.NewTicker(1 * time.Second)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				containers, err := runtimeClient.ListContainers(ctx, &runtimev1.ListContainersRequest{})
				if err != nil {
					logger.Error("failed to list containers", "error", err)
				}
				for _, container := range containers.Containers {
					if container.GetState() != runtimev1.ContainerState_CONTAINER_RUNNING {
						continue
					}

					containerEvent := &runtimev1.ContainerEventResponse{
						ContainerId:        container.GetId(),
						ContainerEventType: runtimev1.ContainerEventType_CONTAINER_CREATED_EVENT,
						CreatedAt:          container.GetCreatedAt(),
					}
					status := &runtimev1.ContainerStatus{
						Metadata: container.GetMetadata(),
						Labels:   container.GetLabels(),
					}

					UpdateForContainer(ctx, logger, containerIDMapperMap, coll, taskClient, containerMaps, status, containerEvent)
				}
			}
		}
	}()

	go func() {
		defer conn.Close()

		for {
			event, err := stream.Recv()
			if err != nil {
				logger.Error("receive CRI container event", "error", err)
				return
			}

			if event.GetContainerEventType() == runtimev1.ContainerEventType_CONTAINER_STOPPED_EVENT {
				continue
			}
			var containerStatus *runtimev1.ContainerStatus
			if event.GetContainerEventType() == runtimev1.ContainerEventType_CONTAINER_CREATED_EVENT || event.GetContainerEventType() == runtimev1.ContainerEventType_CONTAINER_STARTED_EVENT {
				statusResp, err := runtimeClient.ContainerStatus(ctx, &runtimev1.ContainerStatusRequest{ContainerId: event.GetContainerId(), Verbose: true})
				if err != nil && status.Code(err) != codes.NotFound {
					logger.Warn("failed to read created container", "container_id", event.GetContainerId(), "error", err)
				}
				containerStatus = statusResp.GetStatus()
			}

			UpdateForContainer(ctx, logger, containerIDMapperMap, coll, taskClient, containerMaps, containerStatus, event)
		}
	}()

	return containerMaps
}

func UpdateForContainer(ctx context.Context, logger *slog.Logger, containerIDMapperMap map[string]uint32, coll *ebpf.Collection, taskClient tasksvc.TasksClient,
	containerMaps *ContainerMaps, status *runtimev1.ContainerStatus, event *runtimev1.ContainerEventResponse) {

	labels := status.GetLabels()
	namespace := labels["io.kubernetes.pod.namespace"]
	pod := labels["io.kubernetes.pod.name"]
	container := labels["io.kubernetes.container.name"]

	if status != nil && status.GetMetadata() != nil && status.GetMetadata().GetName() != "" {
		container = status.GetMetadata().GetName()
	}
	policyID := uint32(0)
	for pattern, id := range containerIDMapperMap {
		parts := strings.Split(pattern, ":")
		if len(parts) != 3 || !globMatch(parts[0], namespace) || !globMatch(parts[1], pod) || !globMatch(parts[2], container) {
			continue
		}
		if policyID == 0 || id < policyID {
			policyID = id
		}
	}

	containerID := [64]byte{}
	copy(containerID[:], event.GetContainerId())

	var cgroupID uint64
	var hasCgroupID bool
	if event.GetContainerEventType() == runtimev1.ContainerEventType_CONTAINER_DELETED_EVENT {
		cgroupID, hasCgroupID = containerMaps.LookupCgroupID(event.GetContainerId())
		if err := ebpfhelper.DeleteKeyFromMap(coll, ebpfhelper.ContainerIDToContainerContextMapName, containerID); err != nil {
			if !errors.Is(err, ebpf.ErrKeyNotExist) {
				logger.Error("failed to update container id mapper", "error", err)
				return
			}
		}

		if hasCgroupID {
			if err := ebpfhelper.DeleteKeyFromMap(coll, ebpfhelper.CgroupIDToContainerContextMapName, cgroupID); err != nil {
				if errors.Is(err, ebpf.ErrKeyNotExist) {
					containerMaps.Delete(event.GetContainerId())
					return
				}
				logger.Error("failed to update container correlation counter index to container path mapper", "error", err)
				return
			}
		}

		containerMaps.Delete(event.GetContainerId())

	} else if event.GetContainerEventType() == runtimev1.ContainerEventType_CONTAINER_CREATED_EVENT || event.GetContainerEventType() == runtimev1.ContainerEventType_CONTAINER_STARTED_EVENT {
		if err := mapContainerCgroupIDToPath(ctx, taskClient, event.GetContainerId(), containerMaps); err != nil {
			logger.Warn("failed to map container cgroup id", "container_id", event.GetContainerId(), "error", err)
		}

		containerPath := namespace + ":" + pod + ":" + container
		CorrelationIndex := containerMaps.Store(containerPath, event.GetContainerId())
		containerContext := ContainerContext{
			PolicyID:         policyID,
			CorrelationIndex: CorrelationIndex,
		}
		if err := ebpfhelper.UpdateMap(coll, ebpfhelper.ContainerIDToContainerContextMapName, containerID, containerContext); err != nil {
			logger.Error("failed to update container id mapper", "error", err)
			return
		}
		cgroupID, hasCgroupID := containerMaps.LookupCgroupID(event.GetContainerId())
		if hasCgroupID {
			if err := ebpfhelper.UpdateMap(coll, ebpfhelper.CgroupIDToContainerContextMapName, cgroupID, containerContext); err != nil {
				logger.Error("failed to update container correlation counter index to container context mapper", "error", err)
				return
			}
		}
	}
}

func FindCRISocket(ctx context.Context, logger *slog.Logger) string {
	if socketPath := os.Getenv("CRI_SOCKET"); socketPath != "" {
		return socketPath
	}
	if socketPath := os.Getenv("CONTAINERD_SOCK"); socketPath != "" {
		return socketPath
	}
	for _, socketPath := range []string{
		"/run/k3s/containerd/containerd.sock",
		"/run/containerd/containerd.sock",
		"/run/crio/crio.sock",
		"/var/run/cri-dockerd.sock"} {
		if _, err := os.Stat(socketPath); err == nil {
			return socketPath
		}
	}
	return ""
}

func EnsureCgroupV2() error {
	switch cgroups.Mode() {
	case cgroups.Unified:
		return nil
	default:
		return fmt.Errorf("%w: detected mode=%v", ErrCgroupV2Required, cgroups.Mode())
	}
}

// this is used so that we can avoid the vuln in on v1 of containerd
func withContainerdNamespace(ctx context.Context, namespace string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, containerdNamespaceHeader, namespace)
}

func mapContainerCgroupIDToPath(ctx context.Context, taskClient tasksvc.TasksClient, containerID string, containerMaps *ContainerMaps) error {
	ctx = withContainerdNamespace(ctx, "k8s.io")

	taskResp, err := taskClient.Get(ctx, &tasksvc.GetRequest{ContainerID: containerID})
	if err != nil {
		return fmt.Errorf("get task for container %q: %w", containerID, err)
	}
	if taskResp.GetProcess() == nil || taskResp.GetProcess().GetPid() == 0 {
		return fmt.Errorf("container %q has no running task pid", containerID)
	}

	cgroupPath, err := cgroupPathFromPID(int(taskResp.GetProcess().GetPid()))
	if err != nil {
		return err
	}

	cgroupID, err := GetCgroupIdFromPath(cgroupPath)
	if err != nil {
		return err
	}
	containerMaps.StoreCgroupID(containerID, cgroupID)
	return nil
}

func cgroupPathFromPID(pid int) (string, error) {
	p := filepath.Join("/proc", strconv.Itoa(pid), "cgroup")
	_, unified, err := cgroups.ParseCgroupFileUnified(p)
	if err != nil {
		return "", fmt.Errorf("parse %s: %w", p, err)
	}
	if unified == "" {
		return "", fmt.Errorf("cgroup v2 required: no unified path for pid %d", pid)
	}
	return strings.TrimPrefix(unified, "/"), nil
}

func GetCgroupIdFromPath(cgroupPath string) (uint64, error) {
	fullPath := filepath.Join("/sys/fs/cgroup", cgroupPath)
	var stat unix.Stat_t
	if err := unix.Stat(fullPath, &stat); err != nil {
		return 0, fmt.Errorf("stat cgroup path %q: %w", fullPath, err)
	}
	return stat.Ino, nil
}

func globMatch(pattern, value string) bool {
	matched, err := filepath.Match(pattern, value)
	if err != nil {
		return false
	}
	return matched
}
