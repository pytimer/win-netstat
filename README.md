win-netstat
================

[![GoDoc](https://godoc.org/github.com/pytimer/win-netstat?status.svg)](https://godoc.org/github.com/pytimer/win-netstat)

windows netstat implementation in Golang.

## Getting Started

```go
package main

import (
	"fmt"
	"log"

	"github.com/pytimer/win-netstat"
)

func tcp4() {
	conns, err := winnetstat.Connections("tcp4")
	if err != nil {
		log.Fatal(err)
	}
	for _, conn := range conns {
		fmt.Printf("%s:%d\t%d\t%s\n", conn.LocalAddr, conn.LocalPort, conn.OwningPid, conn.State)

	}
}

func tcp4WithPid(pid int) {
	conns, err := winnetstat.ConnectionsWithPid("tcp4", pid)
	if err != nil {
		log.Fatal(err)
	}
	for _, conn := range conns {
		fmt.Printf("%s:%d\t%d\t%s\n", conn.LocalAddr, conn.LocalPort, conn.OwningPid, conn.State)
	}
}

func main() {
	tcp4()
	tcp4WithPid(3848)
}

```

## Examples

[examples](./examples)

## Dependencies

[kbinani/win](https://github.com/kbinani/win)