// +build windows

package winnetstat

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func getTCP4Stat() ([]NetStat, error) {
	var (
		pmibtable PMIB_TCPTABLE_OWNER_PID_ALL
		buf       []byte
		size      uint32
	)

	for {
		if len(buf) > 0 {
			pmibtable = (*MIB_TCPTABLE_OWNER_PID)(unsafe.Pointer(&buf[0]))
		}
		err := GetExtendedTcpTable(uintptr(unsafe.Pointer(pmibtable)),
			&size,
			true,
			syscall.AF_INET,
			TCP_TABLE_OWNER_PID_ALL,
			0)
		if err == nil {
			break
		}
		if err != windows.ERROR_INSUFFICIENT_BUFFER {
			return nil, err
		}
		buf = make([]byte, size)
	}

	if int(pmibtable.DwNumEntries) == 0 {
		return nil, nil
	}

	stats := make([]NetStat, 0)
	index := int(unsafe.Sizeof(pmibtable.DwNumEntries))
	step := int(unsafe.Sizeof(pmibtable.Table))

	// udp no state, so set default state LISTEN
	for i := 0; i < int(pmibtable.DwNumEntries); i++ {
		mibs := (*MIB_TCPROW_OWNER_PID)(unsafe.Pointer(&buf[index]))

		ns := NetStat{
			LocalAddr:  parseIPv4(mibs.DwLocalAddr),
			LocalPort:  decodePort(mibs.DwLocalPort),
			RemoteAddr: parseIPv4(mibs.DwRemoteAddr),
			RemotePort: decodePort(mibs.DwRemotePort),
			OwningPid:  int(mibs.DwOwningPid),
			State:      TCPStatuses[MIB_TCP_STATE(mibs.DwState)],
		}
		stats = append(stats, ns)

		index += step
	}
	return stats, nil
}

func getTCP6Stat() ([]NetStat, error) {
	var (
		pmibtable PMIB_TCP6TABLE_OWNER_PID_ALL
		buf       []byte
		size      uint32
	)

	for {
		if len(buf) > 0 {
			pmibtable = (*MIB_TCP6TABLE_OWNER_PID)(unsafe.Pointer(&buf[0]))
		}
		err := GetExtendedTcpTable(uintptr(unsafe.Pointer(pmibtable)),
			&size,
			true,
			syscall.AF_INET6,
			TCP_TABLE_OWNER_PID_ALL,
			0)
		if err == nil {
			break
		}
		if err != windows.ERROR_INSUFFICIENT_BUFFER {
			return nil, err
		}
		buf = make([]byte, size)
	}

	if int(pmibtable.DwNumEntries) == 0 {
		return nil, nil
	}

	stats := make([]NetStat, 0)
	index := int(unsafe.Sizeof(pmibtable.DwNumEntries))
	step := int(unsafe.Sizeof(pmibtable.Table))

	// udp no state, so set default state LISTEN
	for i := 0; i < int(pmibtable.DwNumEntries); i++ {
		mibs := (*MIB_TCP6ROW_OWNER_PID)(unsafe.Pointer(&buf[index]))

		ns := NetStat{
			LocalAddr:  parseIPv6(mibs.UcLocalAddr),
			LocalPort:  decodePort(mibs.DwLocalPort),
			RemoteAddr: parseIPv6(mibs.UcRemoteAddr),
			RemotePort: decodePort(mibs.DwRemotePort),
			OwningPid:  int(mibs.DwOwningPid),
			State:      TCPStatuses[MIB_TCP_STATE(mibs.DwState)],
		}
		stats = append(stats, ns)

		index += step
	}
	return stats, nil
}

func getTCP4Stat1() ([]NetStat, error) {
	var (
		pmibtable2 PMIB_TCPTABLE2
		buf        []byte
		size       uint32
	)

	for {
		if len(buf) > 0 {
			pmibtable2 = (*MIB_TCPTABLE2)(unsafe.Pointer(&buf[0]))
		}
		err := GetTcpTable2(pmibtable2, &size, true)
		if err == nil {
			break
		}
		// first call to GetTcpTable2 to get the necessary size into the size variable
		// second call to GetTcpTable2 to get the actual data we require
		if err != windows.ERROR_INSUFFICIENT_BUFFER {
			return nil, err
		}
		buf = make([]byte, size)
	}

	if int(pmibtable2.DwNumEntries) == 0 {
		return nil, nil
	}

	stats := make([]NetStat, 0)
	index := int(unsafe.Sizeof(pmibtable2.DwNumEntries))
	step := int(unsafe.Sizeof(pmibtable2.Table))

	for i := 0; i < int(pmibtable2.DwNumEntries); i++ {
		mibs := *(*MIB_TCPROW2)(unsafe.Pointer(&buf[index]))

		ns := NetStat{
			LocalAddr:  parseIPv4(mibs.DwLocalAddr),
			LocalPort:  decodePort(mibs.DwLocalPort),
			RemoteAddr: parseIPv4(mibs.DwRemoteAddr),
			RemotePort: decodePort(mibs.DwRemotePort),
			OwningPid:  int(mibs.DwOwningPid),
			State:      TCPStatuses[MIB_TCP_STATE(mibs.DwState)],
		}
		stats = append(stats, ns)

		index += step
	}
	return stats, nil
}

func getTCP6Stat1() ([]NetStat, error) {
	var (
		pmibtable2 PMIB_TCP6TABLE2
		buf        []byte
		size       uint32
	)

	for {
		if len(buf) > 0 {
			pmibtable2 = (*MIB_TCP6TABLE2)(unsafe.Pointer(&buf[0]))
		}
		// first call to GetTcp6Table2 to get the necessary size into the size variable
		// second call to GetTcp6Table2 to get the actual data we require
		err := GetTcp6Table2(pmibtable2, &size, true)
		if err == nil {
			break
		}
		if err != windows.ERROR_INSUFFICIENT_BUFFER {
			return nil, err
		}
		// alloc the specific size to pmibtable2
		buf = make([]byte, size)
	}

	if int(pmibtable2.DwNumEntries) == 0 {
		return nil, nil
	}

	stats := make([]NetStat, 0)

	index := int(unsafe.Sizeof(pmibtable2.DwNumEntries))
	step := int(unsafe.Sizeof(pmibtable2.Table))

	for i := 0; i < int(pmibtable2.DwNumEntries); i++ {
		mibs := *(*MIB_TCP6ROW2)(unsafe.Pointer(&buf[index]))
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
