package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/urfave/cli"

	"github.com/bomfather/bomfather/agent/config"
	"github.com/bomfather/bomfather/agent/cri"
	"github.com/bomfather/bomfather/agent/ebpf"
	"github.com/bomfather/bomfather/agent/grpcclient"
	"github.com/bomfather/bomfather/agent/helpers"
	"github.com/bomfather/bomfather/agent/metrics"
	"github.com/bomfather/bomfather/agent/proto"
	"github.com/bomfather/bomfather/agent/reader"
	"github.com/bomfather/bomfather/agent/secureshutdown"
	agentstatus "github.com/bomfather/bomfather/agent/status"
)

//go:embed bpf/trace.o
var bpfProgram []byte

const statusFetchTimeout = 5 * time.Second

func main() {
	app := &cli.App{
		Name:  "bomfather Agent",
		Usage: "Real-time security monitoring with eBPF",
		Commands: []cli.Command{
			runCommand(),
			statusCommand(),
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runCommand() cli.Command {
	return cli.Command{
		Name:  "run",
		Usage: "Run the security monitoring agent",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "config, c",
				Usage: "Security policies file (YAML)",
			},
			&cli.StringFlag{
				Name:   "api-key",
				EnvVar: "BOMFATHER_API_KEY",
				Usage:  "Connect to bomfather cloud (or set BOMFATHER_API_KEY)",
			},
			&cli.StringFlag{
				Name:  "api-key-file",
				Usage: "Plain-text file containing API key (mutually exclusive with --api-key)",
			},
			&cli.StringFlag{
				Name:  "verbosity",
				Value: "__NOT_SET__",
				Usage: "Log level: debug|info|warn|error",
			},
			&cli.StringFlag{
				Name:  "metrics-port",
				Value: "9095",
				Usage: "Prometheus metrics (default: 9095, 0=off)",
			},
			&cli.StringFlag{
				Name:   "server",
				EnvVar: "BOMFATHER_SERVER_URL",
				Value:  "https://grpc.bomfather.dev",
				Usage:  "Server URL ( grpc://, or https://). Examples: grpc://localhost:5000, https://grpc.bomfather.dev",
			},

			&cli.StringFlag{
				Name:   "api-server-url",
				EnvVar: "BOMFATHER_API_SERVER_URL",
				Value:  "https://api.bomfather.dev",
				Usage:  "API server URL for key verification (default: https://api.bomfather.dev)",
			},
			&cli.BoolFlag{
				Name:  "enable-debug-logging",
				Usage: "Enable verbose eBPF printk debug logs (default: off)",
			},
			&cli.IntFlag{
				Name:   "grpc-buffer-size",
				EnvVar: "BOMFATHER_GRPC_BUFFER_SIZE",
				Value:  10000,
				Usage:  "Ring buffer capacity for offline events (gRPC only)",
			},
			&cli.IntFlag{
				Name:   "grpc-batch-size",
				EnvVar: "BOMFATHER_GRPC_BATCH_SIZE",
				Value:  100,
				Usage:  "Events per batch before sending (gRPC only)",
			},
			&cli.DurationFlag{
				Name:   "grpc-batch-interval",
				EnvVar: "BOMFATHER_GRPC_BATCH_INTERVAL",
				Value:  100 * time.Millisecond,
				Usage:  "Max wait before flush (gRPC only)",
			},
		},
		Action: func(c *cli.Context) error {
			return runAgent(c)
		},
	}
}

func statusCommand() cli.Command {
	return cli.Command{
		Name:  "status",
		Usage: "Show the status of a running agent",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "json",
				Usage: "Print full status as JSON",
			},
			&cli.StringFlag{
				Name:  "metrics-host",
				Value: agentstatus.DefaultMetricsHost,
				Usage: "Host used by the running agent's metrics server",
			},
			&cli.StringFlag{
				Name:  "metrics-port",
				Value: "9095",
				Usage: "Port used by the running agent's metrics server",
			},
		},
		Action: func(c *cli.Context) error {
			ctx, cancel := context.WithTimeout(context.Background(), statusFetchTimeout)
			defer cancel()

			families, err := agentstatus.NewClient(c.String("metrics-host"), c.String("metrics-port")).Fetch(ctx)
			if err != nil {
				return fmt.Errorf("query running agent: %w", err)
			}
			report := agentstatus.NewReport(families)
			if !c.Bool("json") {
				_, err := fmt.Fprint(c.App.Writer, report.Summary())
				return err
			}
			encoder := json.NewEncoder(c.App.Writer)
			encoder.SetIndent("", "  ")
			return encoder.Encode(report)
		},
	}
}

func runAgent(c *cli.Context) error {
	helpers.PrintBanner()

	apiKey, err := helpers.ResolveAPIKey(c.String("api-key"), c.String("api-key-file"))
	if err != nil {
		return err
	}

	verbosity := c.String("verbosity")
	level := slog.LevelInfo
	logLevel := map[string]slog.Level{
		"debug": slog.LevelDebug,
		"info":  slog.LevelInfo,
		"warn":  slog.LevelWarn,
		"error": slog.LevelError,
	}
	if mapLevel, ok := logLevel[strings.TrimSpace(verbosity)]; ok { // if we don't find the level, we use the default level
		level = mapLevel
	}

	logOutput := io.Writer(os.Stdout)
	if c.Bool("enable-debug-logging") {
		logFile, stopTracePipeForwarding, err := helpers.StartTracePipeForwarding()
		if err != nil {
			return err
		}
		defer stopTracePipeForwarding()
		logOutput = logFile
	}

	logger := slog.New(slog.NewJSONHandler(logOutput, &slog.HandlerOptions{
		Level: level,
	}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	registry, agentMetrics := metrics.NewRegistry()
	agentMetrics.SetBuildInfo(grpcclient.Version, grpcclient.Commit)
	if metricsPort := c.String("metrics-port"); metricsPort != "0" {
		metricsServer := metrics.NewServer(registry, metrics.WithPort(metricsPort))

		listener, err := net.Listen("tcp", metricsServer.Server.Addr)
		if err != nil {
			return fmt.Errorf("failed to start metrics server: %w", err)
		}
		defer metricsServer.Server.Close()

		agentMetrics.StartTime.SetToCurrentTime()
		go func() {
			if err := metricsServer.Server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("metrics server failed", "error", err)
				cancel()
			}
		}()
	}

	cfg, ebpfMapWrites, containerIDMapperMap, networkIDMapper, networkToConvert, err := config.ParseConfig(c.String("config"), c.Bool("enable-debug-logging"))
	if err != nil {
		logger.Error("failed to parse config", "error", err)
		return err
	}

	if config.HasFsVerityDigests(cfg) {
		if supported, kErr := ebpf.IsFsVeritySupported(); kErr != nil {
			logger.Warn("could not determine kernel version for fs-verity support", "error", kErr)
		} else if !supported {
			logger.Warn("fsverity_digest is configured but kernel < 6.8 does not support bpf_get_fsverity_digest; digest enforcement is disabled")
		}
	}

	secureShutdownEnabled := cfg.ShutdownConfig.Port != "" && cfg.ShutdownConfig.PublicKey != ""
	if secureShutdownEnabled {
		rsaPub, err := secureshutdown.ParsePublicKey(cfg.ShutdownConfig.PublicKey)
		if err != nil {
			logger.Error("failed to parse public key", "error", err)
			return err
		}

		go func() {
			if apiErr := secureshutdown.StartAPIServer(ctx, cfg.ShutdownConfig.Port, logger, cancel, rsaPub, agentMetrics); apiErr != nil {
				logger.Error("failed to start secure shutdown API server", "error", apiErr)
				cancel()
			}
		}()
	}

	var client grpcclient.Client
	if apiKey != "" {
		agentMetrics.SetComponentState(metrics.ComponentAPIKey, metrics.StateStarting)
		agentMetrics.SetComponentState(metrics.ComponentGRPC, metrics.StateStarting)
		err = helpers.VerifyAPIKey(ctx, c.String("api-server-url"), apiKey)
		if err != nil {
			agentMetrics.SetComponentState(metrics.ComponentAPIKey, metrics.StateDegraded)
			agentMetrics.SetComponentState(metrics.ComponentGRPC, metrics.StateDegraded)
			logger.Error("failed to verify API key", "error", err)
			return err
		}
		agentMetrics.SetComponentState(metrics.ComponentAPIKey, metrics.StateRunning)
		serverURL := strings.TrimSpace(c.String("server"))
		client, err = grpcclient.NewDefaultClient(serverURL, apiKey, agentMetrics)
		if err != nil {
			agentMetrics.SetComponentState(metrics.ComponentGRPC, metrics.StateDegraded)
			logger.Error("failed to create gRPC client", "error", err)
			return err
		}
	} else {
		agentMetrics.SetComponentState(metrics.ComponentAPIKey, metrics.StateDisabled)
		agentMetrics.SetComponentState(metrics.ComponentGRPC, metrics.StateDisabled)
		client = grpcclient.NewDummyClient()
	}

	client.StartHealthcheck(ctx, logger)

	streams := reader.EventStreams{
		OpenatStream:    make(chan *proto.OpenatEventWrapper),
		ExecveStream:    make(chan *proto.ExecveEventWrapper),
		ViolationStream: make(chan *proto.ViolationEventWrapper),
	}

	client.ConsumeEvents(ctx, logger, streams, c.Int("grpc-buffer-size"), c.Int("grpc-batch-size"), c.Duration("grpc-batch-interval"))

	nodeId, err := client.GetOrCreateNode(ctx, logger)
	if err != nil {
		logger.Error("failed to get or create node", "error", err)
		return err
	}

	ebpfResources, err := ebpf.InitializeEBPF(bpfProgram, ebpfMapWrites, secureShutdownEnabled, cfg.Flags.SecureMaps, cfg.Flags.DisableBPFOps)
	if err != nil {
		logger.Error("failed to initialize eBPF", "error", err)
		return err
	}
	defer ebpfResources.Close()

	config.RefreshDNSPolicy(ctx, logger, ebpfResources.Collection, networkIDMapper, networkToConvert)

	if err := cri.EnsureCgroupV2(); err != nil {
		logger.Error("failed to ensure cgroup v2", "error", err)
		return fmt.Errorf("failed to ensure cgroup v2: %w", err)
	}

	var cgroupToContainer *cri.ContainerMaps
	socketPath := cri.FindCRISocket(ctx, logger)
	if socketPath != "" {
		cgroupToContainer = cri.UpdateEBPFContainerContext(ctx, logger, containerIDMapperMap, socketPath, ebpfResources.Collection)
	} else {
		logger.Info("No CRI socket found, container monitoring disabled")
	}

	logger.Info("eBPF security policies launched successfully")

	reader.ReadEvents(ctx, logger, *ebpfResources, nodeId, streams, cgroupToContainer)

	logger.Info("Agent shutdown", "status", "stopped")
	return nil
}
