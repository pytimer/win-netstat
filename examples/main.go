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

func tcp6() {
	conns, err := winnetstat.Connections("tcp6")
	if err != nil {
		log.Fatal(err)
	}
	for _, conn := range conns {
		fmt.Printf("[%s]:%d\t%d\t%s\n", conn.LocalAddr, conn.LocalPort, conn.OwningPid, conn.State)
	}
}

func tcp6WithPid(pid int) {
	conns, err := winnetstat.ConnectionsWithPid("tcp6", pid)
	if err != nil {
		log.Fatal(err)
	}
	for _, conn := range conns {
		fmt.Printf("[%s]:%d\t%d\t%s\n", conn.LocalAddr, conn.LocalPort, conn.OwningPid, conn.State)
	}
}

func udp4() {
	conns, err := winnetstat.Connections("udp4")
	if err != nil {
		log.Fatal(err)
	}
	for _, conn := range conns {
		fmt.Printf("%s:%d\t%d\t\n", conn.LocalAddr, conn.LocalPort, conn.OwningPid)
	}
}

func udp4WithPid(pid int) {
	conns, err := winnetstat.ConnectionsWithPid("udp4", pid)
	if err != nil {
		log.Fatal(err)
	}
	for _, conn := range conns {
		fmt.Printf("%s:%d\t%d\t\n", conn.LocalAddr, conn.LocalPort, conn.OwningPid)
	}
}

func udp6() {
	conns, err := winnetstat.Connections("udp6")
	if err != nil {
		log.Fatal(err)
	}
	for _, conn := range conns {
		fmt.Printf("[%s]:%d\t%d\t\n", conn.LocalAddr, conn.LocalPort, conn.OwningPid)
	}
}

func udp6WithPid(pid int) {
	conns, err := winnetstat.ConnectionsWithPid("udp6", pid)
	if err != nil {
		log.Fatal(err)
	}
	for _, conn := range conns {
		fmt.Printf("[%s]:%d\t%d\t\n", conn.LocalAddr, conn.LocalPort, conn.OwningPid)
	}
}

func inet() {
	conns, err := winnetstat.Connections("all")
	if err != nil {
		log.Fatal(err)
	}
	for _, conn := range conns {
		fmt.Printf("[%s]:%d\t%d\t\n", conn.LocalAddr, conn.LocalPort, conn.OwningPid)
	}
}

func main() {
	// tcp4()
	// tcp4WithPid(3848)
	// tcp6()
	// tcp6WithPid(2368)
	// udp4()
	// udp4WithPid(4592)
	// udp6()
	// udp6WithPid(4592)
	inet()
}
