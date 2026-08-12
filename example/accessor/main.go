package main

import (
	"fmt"
	"os"
)

const protectedPath = "../protected/protected1/protected.txt"

func readProtectedFile() error {
	output, err := os.ReadFile(protectedPath)
	if err != nil {
		return err
	}

	fmt.Printf("Read %s:\n%s\n", protectedPath, output)
	return nil
}

func main() {
	if err := readProtectedFile(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to read protected file: %v\n", err)
		os.Exit(1)
	}
}
