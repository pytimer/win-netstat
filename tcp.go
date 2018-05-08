package winnetstat

import (
	"fmt"
	"unsafe"

	"github.com/kbinani/win"
)

func getTCP4Stat() ([]NetStat, error) {
	var pmibtable2 win.PMIB_TCPTABLE2
	var mibtable2 win.MIB_TCPTABLE2

	size := unsafe.Sizeof(mibtable2)
	pmibtable2 = &mibtable2

	// first call to GetTcpTable2 to get the necessary size into the size variable
	ret := win.GetTcpTable2(pmibtable2, (*uint32)(unsafe.Pointer(&size)), true)
	if ret == ErrInsufficientBuffer {
		// alloc the specific size to pmibtable2
		buf := make([]byte, size)
		pmibtable2 = (*win.MIB_TCPTABLE2)(unsafe.Pointer(&buf[0]))

		// second call to GetTcpTable2 to get the actual data we require
		dwRet := win.GetTcpTable2(pmibtable2, (*uint32)(unsafe.Pointer(&size)), true)
		if int(dwRet) != 0 {
			return nil, fmt.Errorf("run GetTcpTable2 error")
		}

		stats := make([]NetStat, 0)

		index := int(unsafe.Sizeof(pmibtable2.DwNumEntries))
		step := int(unsafe.Sizeof(pmibtable2.Table))

		for i := 0; i < int(pmibtable2.DwNumEntries); i++ {
			mibs := *(*win.MIB_TCPROW2)(unsafe.Pointer(&buf[index]))

			ns := NetStat{
				LocalAddr:  parseIPv4(mibs.DwLocalAddr),
				LocalPort:  decodePort(mibs.DwLocalPort),
				RemoteAddr: parseIPv4(mibs.DwRemoteAddr),
				RemotePort: decodePort(mibs.DwRemotePort),
				OwningPid:  int(mibs.DwOwningPid),
				State:      TCPStatuses[win.MIB_TCP_STATE(mibs.DwState)],
			}
			stats = append(stats, ns)

			index += step
		}
		return stats, nil
	}
	return nil, fmt.Errorf("allocating memory error, %v", ret)
}

func getTCP6Stat() ([]NetStat, error) {
	var pmibtable2 win.PMIB_TCP6TABLE2
	var mibtable2 win.MIB_TCP6TABLE2

	size := unsafe.Sizeof(mibtable2)
	pmibtable2 = &mibtable2

	// first call to GetTcp6Table2 to get the necessary size into the size variable
	ret := win.GetTcp6Table2(pmibtable2, (*uint32)(unsafe.Pointer(&size)), true)
	if ret == ErrInsufficientBuffer {
		// alloc the specific size to pmibtable2
		buf := make([]byte, size)
		pmibtable2 = (*win.MIB_TCP6TABLE2)(unsafe.Pointer(&buf[0]))
		// second call to GetTcp6Table2 to get the actual data we require
		dwRet := win.GetTcp6Table2(pmibtable2, (*uint32)(unsafe.Pointer(&size)), true)
		if int(dwRet) != 0 {
			return nil, fmt.Errorf("run GetTcp6Table2 error")
		}

		stats := make([]NetStat, 0)

		index := int(unsafe.Sizeof(pmibtable2.DwNumEntries))
		step := int(unsafe.Sizeof(pmibtable2.Table))

		for i := 0; i < int(pmibtable2.DwNumEntries); i++ {
			mibs := *(*win.MIB_TCP6ROW2)(unsafe.Pointer(&buf[index]))
			ns := NetStat{
				LocalAddr:  parseIPv6(mibs.LocalAddr.U.GetByte()),
				LocalPort:  decodePort(mibs.DwLocalPort),
				RemoteAddr: parseIPv6(mibs.RemoteAddr.U.GetByte()),
				RemotePort: decodePort(mibs.DwRemotePort),
				OwningPid:  int(mibs.DwOwningPid),
				State:      TCPStatuses[mibs.State],
			}
			stats = append(stats, ns)

			index += step
		}
		return stats, nil
	}
	return nil, fmt.Errorf("allocating memory error, %v", ret)
}
