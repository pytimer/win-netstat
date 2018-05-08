// +build windows

package winnetstat

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/kbinani/win"
)

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa365930(v=vs.85).aspx
type MIB_UDPROW_OWNER_PID struct {
	DwLocalAddr win.DWORD
	DwLocalPort win.DWORD
	DwOwningPid win.DWORD
}

type MIB_UDPTABLE_OWNER_PID struct {
	DwNumEntries win.DWORD
	Table        [win.ANY_SIZE]MIB_UDPROW_OWNER_PID
}

type PMIB_UDPTABLE_OWNER_PID *MIB_UDPTABLE_OWNER_PID

type MIB_UDP6ROW_OWNER_PID struct {
	UcLocalAddr    [16]win.UCHAR
	DwLocalScopeId win.DWORD
	DwLocalPort    win.DWORD
	DwOwningPid    win.DWORD
}

type MIB_UDP6TABLE_OWNER_PID struct {
	DwNumEntries win.DWORD
	Table        [win.ANY_SIZE]MIB_UDP6ROW_OWNER_PID
}

type PMIB_UDP6TABLE_OWNER_PID *MIB_UDP6TABLE_OWNER_PID

func getUDP4Stat() ([]NetStat, error) {
	var pmibtable2 PMIB_UDPTABLE_OWNER_PID
	var mibtable2 MIB_UDPTABLE_OWNER_PID

	size := unsafe.Sizeof(mibtable2)
	pmibtable2 = &mibtable2

	// first call to GetExtendedUdpTable to get the necessary size into the size variable
	ret := win.GetExtendedUdpTable(
		uintptr(unsafe.Pointer(pmibtable2)),
		(*win.DWORD)(unsafe.Pointer(&size)),
		true,
		win.AF_INET,
		win.UDP_TABLE_OWNER_PID,
		0,
	)
	if ret == ErrInsufficientBuffer {
		buf := make([]byte, size)
		pmibtable2 = (*MIB_UDPTABLE_OWNER_PID)(unsafe.Pointer(&buf[0]))

		// second call to GetExtendedUdpTable to get the actual data we require
		dwRet := win.GetExtendedUdpTable(
			uintptr(unsafe.Pointer(pmibtable2)),
			(*win.DWORD)(unsafe.Pointer(&size)),
			true,
			syscall.AF_INET,
			win.UDP_TABLE_OWNER_PID,
			0,
		)
		if int(dwRet) != 0 {
			return nil, fmt.Errorf("run GetExtendedUdpTable error")
		}

		stats := make([]NetStat, 0)
		index := int(unsafe.Sizeof(pmibtable2.DwNumEntries))
		step := int(unsafe.Sizeof(pmibtable2.Table))

		for i := 0; i < int(pmibtable2.DwNumEntries); i++ {
			mibs := (*MIB_UDPROW_OWNER_PID)(unsafe.Pointer(&buf[index]))

			ns := NetStat{
				LocalAddr: parseIPv4(mibs.DwLocalAddr),
				LocalPort: decodePort(mibs.DwLocalPort),
				OwningPid: int(mibs.DwOwningPid),
			}
			stats = append(stats, ns)

			index += step
		}
		return stats, nil
	}

	return nil, fmt.Errorf("allocating memory error, %v", ret)
}

func getUDP6Stat() ([]NetStat, error) {
	var pmibtable2 PMIB_UDP6TABLE_OWNER_PID
	var mibtable2 MIB_UDP6TABLE_OWNER_PID

	size := unsafe.Sizeof(mibtable2)
	pmibtable2 = &mibtable2

	// first call to GetExtendedUdpTable to get the necessary size into the size variable
	ret := win.GetExtendedUdpTable(
		uintptr(unsafe.Pointer(pmibtable2)),
		(*win.DWORD)(unsafe.Pointer(&size)),
		true,
		win.AF_INET6,
		win.UDP_TABLE_OWNER_PID,
		0,
	)
	if ret == ErrInsufficientBuffer {
		buf := make([]byte, size)
		pmibtable2 = (*MIB_UDP6TABLE_OWNER_PID)(unsafe.Pointer(&buf[0]))

		// second call to GetExtendedUdpTable to get the actual data we require
		dwRet := win.GetExtendedUdpTable(
			uintptr(unsafe.Pointer(pmibtable2)),
			(*win.DWORD)(unsafe.Pointer(&size)),
			true,
			syscall.AF_INET6,
			win.UDP_TABLE_OWNER_PID,
			0,
		)
		if int(dwRet) != 0 {
			return nil, fmt.Errorf("run GetExtendedUdp6Table error")
		}

		stats := make([]NetStat, 0)
		index := int(unsafe.Sizeof(pmibtable2.DwNumEntries))
		step := int(unsafe.Sizeof(pmibtable2.Table))

		for i := 0; i < int(pmibtable2.DwNumEntries); i++ {

			mibs := (*MIB_UDP6ROW_OWNER_PID)(unsafe.Pointer(&buf[index]))
			ns := NetStat{
				LocalAddr: parseIPv6(mibs.UcLocalAddr),
				LocalPort: decodePort(mibs.DwLocalPort),
				OwningPid: int(mibs.DwOwningPid),
			}
			stats = append(stats, ns)

			index += step
		}
		return stats, nil
	}

	return nil, fmt.Errorf("allocating memory error, %v", ret)
}
