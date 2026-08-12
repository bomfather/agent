package main

import (
	"fmt"
	"os"
	"path/filepath"
)

const protectedPath = "../protected/protected1/protected.txt"

func readProtectedFile() error {
	executablePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}

	resolvedProtectedPath := filepath.Clean(filepath.Join(filepath.Dir(executablePath), protectedPath))

	output, err := os.ReadFile(resolvedProtectedPath)
	if err != nil {
		return fmt.Errorf("read protected file %q: %w", resolvedProtectedPath, err)
	}

	fmt.Printf("Read %s:\n%s\n", resolvedProtectedPath, output)
	return nil
}

func main() {
	if err := readProtectedFile(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to read protected file: %v\n", err)
		os.Exit(1)
	}
}
