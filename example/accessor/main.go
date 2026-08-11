package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

const protectedPath = "../protected/protected1/protected.txt"

func readProtectedFile() {
	file, err := os.Open(protectedPath)
	if err != nil {
		return
	}
	defer file.Close()

	output, err := io.ReadAll(file)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(string(output))
}

func main() {
	readProtectedFile()
	readProtectedFile()

	conn, err := net.Dial("tcp", "google.com:80")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer conn.Close()

	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			request := "GET / HTTP/1.1\r\nHost: google.com\r\nConnection: keep-alive\r\n\r\n"
			if _, err := conn.Write([]byte(request)); err != nil {
				fmt.Println("write failed:", err)
				return
			}

			<-ticker.C
		}
	}()

	buffer := make([]byte, 4096)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			fmt.Println("read failed:", err)
			return
		}

		if n > 0 {
			fmt.Println(string(buffer[:n]))
		}
	}
}
