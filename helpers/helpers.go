package helpers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const logFilePath = "agent_debug.log"

func ResolveAPIKey(inlineKey, apiKeyFile string) (string, error) {
	trimmedInlineKey := strings.TrimSpace(inlineKey)
	trimmedAPIKeyFile := strings.TrimSpace(apiKeyFile)

	if trimmedInlineKey != "" && trimmedAPIKeyFile != "" {
		return "", fmt.Errorf("cannot specify both --api-key and --api-key-file; use one or the other")
	}

	if trimmedAPIKeyFile == "" {
		return trimmedInlineKey, nil
	}

	apiKeyBytes, err := os.ReadFile(trimmedAPIKeyFile)
	if err != nil {
		return "", fmt.Errorf("failed to read api key file: %w", err)
	}

	apiKey := strings.TrimSpace(string(apiKeyBytes))
	if apiKey == "" {
		return "", fmt.Errorf("api key file is empty or contains only whitespace")
	}

	return apiKey, nil
}

func VerifyAPIKey(ctx context.Context, serverURL, apiKey string) error {
	if serverURL == "" || apiKey == "" {
		return nil
	}

	requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(
		requestCtx,
		http.MethodGet,
		strings.TrimSuffix(serverURL, "/")+"/users/verify",
		nil,
	)
	if err != nil {
		return err
	}

	req.Header.Set("X-API-Key", apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return nil
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("invalid API key")
	}
	return fmt.Errorf("API key verification failed: HTTP %d", resp.StatusCode)
}

func PrintBanner() {
	fmt.Print(`
 ____                   __      __  __
| __ )  ___  _ __ ___  / _| __ _| |_| |__   ___ _ __
|  _ \ / _ \| '_ ' _ \| |_ / _' | __| '_ \ / _ \ '__|
| |_) | (_) | | | | | |  _| (_| | |_| | | |  __/ |
|____/ \___/|_| |_| |_|_|  \__,_|\__|_| |_|\___|_|

Real-time security monitoring with eBPF

`)
}

// StartTracePipeForwarding appends kernel bpf_printk output from trace_pipe into
// the debug log file and returns the combined log writer plus a shutdown function.
func StartTracePipeForwarding() (io.Writer, func() error, error) {
	logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, nil, fmt.Errorf("open log file: %w", err)
	}

	traceReader, err := os.Open("/sys/kernel/debug/tracing/trace_pipe")
	if err != nil {
		_ = logFile.Close()
		return nil, nil, fmt.Errorf("open trace_pipe: %w", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(logFile, traceReader)
		done <- err
	}()

	shouldLogTo := io.MultiWriter(logFile, os.Stdout)

	stop := func() error {
		_ = traceReader.Close()
		err := <-done
		if isClosedFileError(err) {
			err = nil
		}
		closeErr := logFile.Close()
		if err != nil {
			return fmt.Errorf("failed to copy trace_pipe to log file: %w", err)
		}
		if closeErr != nil {
			return fmt.Errorf("close debug log file: %w", closeErr)
		}
		return nil
	}

	return shouldLogTo, stop, nil
}

func isClosedFileError(err error) bool {
	return err != nil && (errors.Is(err, os.ErrClosed) || strings.Contains(err.Error(), "file already closed"))
}
