// +build windows

package winnetstat

import (
	"syscall"
)

const ANY_SIZE = 1

type MIB_TCP_STATE int32

type TCP_CONNECTION_OFFLOAD_STATE int32

const (
	TcpConnectionOffloadStateInHost TCP_CONNECTION_OFFLOAD_STATE = iota
	TcpConnectionOffloadStateOffloading
	TcpConnectionOffloadStateOffloaded
	TcpConnectionOffloadStateUploading
	TcpConnectionOffloadStateMax
)

type MIB_TCPROW2 struct {
	DwState        uint32
	DwLocalAddr    uint32
	DwLocalPort    uint32
	DwRemoteAddr   uint32
	DwRemotePort   uint32
	DwOwningPid    uint32
	DwOffloadState TCP_CONNECTION_OFFLOAD_STATE
}

type MIB_TCPTABLE2 struct {
	DwNumEntries uint32
	Table        [ANY_SIZE]MIB_TCPROW2
}

type PMIB_TCPTABLE2 *MIB_TCPTABLE2
type PMIB_TCP6TABLE2 *MIB_TCP6TABLE2

func doLoadLibrary(name string) uintptr {
	lib, _ := syscall.LoadLibrary(name)
	return uintptr(lib)
}

type IN6_ADDR_U struct {
	Uchar  [16]byte
	Ushort [8]uint16
}

type IN6_ADDR struct {
	U IN6_ADDR_U
}

func (u *IN6_ADDR_U) GetByte() [16]byte {
	var ret [16]byte
	for i := 0; i < 16; i++ {
		ret[i] = u.Uchar[i]
	}
	return ret
}

type MIB_TCP6ROW2 struct {
	LocalAddr       IN6_ADDR
	DwLocalScopeId  uint32
	DwLocalPort     uint32
	RemoteAddr      IN6_ADDR
	DwRemoteScopeId uint32
	DwRemotePort    uint32
	State           MIB_TCP_STATE
	DwOwningPid     uint32
	DwOffloadState  TCP_CONNECTION_OFFLOAD_STATE
}

type MIB_TCP6TABLE2 struct {
	DwNumEntries uint32
	Table        [ANY_SIZE]MIB_TCP6ROW2
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa365930(v=vs.85).aspx
type MIB_UDPROW_OWNER_PID struct {
	DwLocalAddr uint32
	DwLocalPort uint32
	DwOwningPid uint32
}

type MIB_UDPTABLE_OWNER_PID struct {
	DwNumEntries uint32
	Table        [ANY_SIZE]MIB_UDPROW_OWNER_PID
}

type PMIB_UDPTABLE_OWNER_PID *MIB_UDPTABLE_OWNER_PID

type MIB_UDP6ROW_OWNER_PID struct {
	UcLocalAddr    [16]byte
	DwLocalScopeId uint32
	DwLocalPort    uint32
	DwOwningPid    uint32
}

type MIB_UDP6TABLE_OWNER_PID struct {
	DwNumEntries uint32
	Table        [ANY_SIZE]MIB_UDP6ROW_OWNER_PID
}

type UDP_TABLE_CLASS int32

const (
	UDP_TABLE_BASIC UDP_TABLE_CLASS = iota
	UDP_TABLE_OWNER_PID
	UDP_TABLE_OWNER_MODULE
)

type PMIB_UDP6TABLE_OWNER_PID *MIB_UDP6TABLE_OWNER_PID

// GetExtendedTcpTable TCP4 struct

type MIB_TCPROW_OWNER_PID struct {
	DwState      uint32
	DwLocalAddr  uint32
	DwLocalPort  uint32
	DwRemoteAddr uint32
	DwRemotePort uint32
	DwOwningPid  uint32
}
type MIB_TCPTABLE_OWNER_PID struct {
	DwNumEntries uint32
	Table        [ANY_SIZE]MIB_TCPROW_OWNER_PID
}
type PMIB_TCPTABLE_OWNER_PID_ALL *MIB_TCPTABLE_OWNER_PID

// GetExtendedTcpTable TCP6 struct

type MIB_TCP6ROW_OWNER_PID struct {
	UcLocalAddr     [16]byte
	DwLocalScopeId  uint32
	DwLocalPort     uint32
	UcRemoteAddr    [16]byte
	DwRemoteScopeId uint32
	DwRemotePort    uint32
	DwState         uint32
	DwOwningPid     uint32
}

type MIB_TCP6TABLE_OWNER_PID struct {
	DwNumEntries uint32
	Table        [ANY_SIZE]MIB_TCP6ROW_OWNER_PID
}

type PMIB_TCP6TABLE_OWNER_PID_ALL *MIB_TCP6TABLE_OWNER_PID

type TCP_TABLE_CLASS int32

const (
	TCP_TABLE_BASIC_LISTENER TCP_TABLE_CLASS = iota
	TCP_TABLE_BASIC_CONNECTIONS
	TCP_TABLE_BASIC_ALL
	TCP_TABLE_OWNER_PID_LISTENER
	TCP_TABLE_OWNER_PID_CONNECTIONS
	TCP_TABLE_OWNER_PID_ALL
	TCP_TABLE_OWNER_MODULE_LISTENER
	TCP_TABLE_OWNER_MODULE_CONNECTIONS
	TCP_TABLE_OWNER_MODULE_ALL
)
