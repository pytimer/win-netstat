// +build windows

package winnetstat

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	// Library
	modiphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")

	// Functions
	procGetTCPTable2        = modiphlpapi.NewProc("GetTcpTable2")
	procGetTCP6Table2       = modiphlpapi.NewProc("GetTcp6Table2")
	procGetExtendedTCPTable = modiphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUDPTable = modiphlpapi.NewProc("GetExtendedUdpTable")
)

func getUintptrFromBool(b bool) uintptr {
	if b {
		return 1
	}
	return 0
}

func GetTcpTable2(tcpTable PMIB_TCPTABLE2, bufSize *uint32, order bool) (errcode error) {
	r1, _, _ := syscall.Syscall(procGetTCPTable2.Addr(), 3, uintptr(unsafe.Pointer(tcpTable)), uintptr(unsafe.Pointer(bufSize)), getUintptrFromBool(order))
	if r1 != 0 {
		errcode = syscall.Errno(r1)
	}
	return
}

func GetTcp6Table2(tcpTable PMIB_TCP6TABLE2, bufSize *uint32, order bool) (errcode error) {
	r1, _, _ := syscall.Syscall(procGetTCP6Table2.Addr(), 3, uintptr(unsafe.Pointer(tcpTable)), uintptr(unsafe.Pointer(bufSize)), getUintptrFromBool(order))
	if r1 != 0 {
		errcode = syscall.Errno(r1)
	}
	return
}

func GetExtendedUdpTable(pUdpTable uintptr, pdwSize *uint32, bOrder bool, ulAf uint32, tableClass UDP_TABLE_CLASS, reserved uint32) (errcode error) {
	r1, _, _ := syscall.Syscall6(procGetExtendedUDPTable.Addr(), 6, pUdpTable, uintptr(unsafe.Pointer(pdwSize)), getUintptrFromBool(bOrder), uintptr(ulAf), uintptr(tableClass), uintptr(reserved))
	if r1 != 0 {
		errcode = syscall.Errno(r1)
	}
	return
}

func GetExtendedTcpTable(pTcpTable uintptr, pdwSize *uint32, bOrder bool, ulAf uint32, tableClass TCP_TABLE_CLASS, reserved uint32) (errcode error) {
	r1, _, _ := syscall.Syscall6(procGetExtendedTCPTable.Addr(), 6, pTcpTable, uintptr(unsafe.Pointer(pdwSize)), getUintptrFromBool(bOrder), uintptr(ulAf), uintptr(tableClass), uintptr(reserved))
	if r1 != 0 {
		errcode = syscall.Errno(r1)
	}
	return
}
