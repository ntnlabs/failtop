// main.go
package main

import (
	"fmt"
	"os"
)

func main() {
	if os.Getuid() != 0 {
		fmt.Fprintln(os.Stderr, "failtop: must be run as root")
		os.Exit(1)
	}
	fmt.Println("failtop starting...")
}
