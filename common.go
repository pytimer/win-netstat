// +build windows

package winnetstat

import (
	"fmt"
	"net"
	"syscall"
)

func decodePort(port uint32) uint16 {
	return syscall.Ntohs(uint16(port))
}

func parseIPv4(addr uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", addr&255, addr>>8&255, addr>>16&255, addr>>24&255)
}

func parseIPv6(addr [16]byte) string {
	var ret [16]byte
	for i := 0; i < 16; i++ {
		ret[i] = uint8(addr[i])
	}

	// convert []byte to net.IP
	ip := net.IP(ret[:])
	return ip.String()
}

// TCPStatuses https://msdn.microsoft.com/en-us/library/windows/desktop/bb485761(v=vs.85).aspx
var TCPStatuses = map[MIB_TCP_STATE]string{
	1:  "CLOSED",
	2:  "LISTEN",
	3:  "SYN_SENT",
	4:  "SYN_RECEIVED",
	5:  "ESTABLISHED",
	6:  "FIN_WAIT_1",
	7:  "FIN_WAIT_2",
	8:  "CLOSE_WAIT",
	9:  "CLOSING",
	10: "LAST_ACK",
	11: "TIME_WAIT",
	12: "DELETE",
}
