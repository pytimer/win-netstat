// +build windows

package winnetstat

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func getUDP4Stat() ([]NetStat, error) {
	var (
		pmibtable2 PMIB_UDPTABLE_OWNER_PID
		size       uint32
		buf        []byte
	)

	for {
		if len(buf) > 0 {
			pmibtable2 = (*MIB_UDPTABLE_OWNER_PID)(unsafe.Pointer(&buf[0]))
		}
		err := GetExtendedUdpTable(
			uintptr(unsafe.Pointer(pmibtable2)),
			&size,
			true,
			syscall.AF_INET,
			UDP_TABLE_OWNER_PID,
			0,
		)
		if err == nil {
			break
		}
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

	// udp no state, so set default state LISTEN
	for i := 0; i < int(pmibtable2.DwNumEntries); i++ {
		mibs := (*MIB_UDPROW_OWNER_PID)(unsafe.Pointer(&buf[index]))

		ns := NetStat{
			LocalAddr: parseIPv4(mibs.DwLocalAddr),
			LocalPort: decodePort(mibs.DwLocalPort),
			OwningPid: int(mibs.DwOwningPid),
			State:     TCPStatuses[2],
		}
		stats = append(stats, ns)

		index += step
	}
	return stats, nil

}

func getUDP6Stat() ([]NetStat, error) {
	var (
		pmibtable2 PMIB_UDP6TABLE_OWNER_PID
		buf        []byte
		size       uint32
	)

	for {
		if len(buf) > 0 {
			pmibtable2 = (*MIB_UDP6TABLE_OWNER_PID)(unsafe.Pointer(&buf[0]))
		}
		err := GetExtendedUdpTable(
			uintptr(unsafe.Pointer(pmibtable2)),
			(*uint32)(unsafe.Pointer(&size)),
			true,
			syscall.AF_INET6,
			UDP_TABLE_OWNER_PID,
			0,
		)
		if err == nil {
			break
		}
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
	// udp no state, so set default state LISTEN
	for i := 0; i < int(pmibtable2.DwNumEntries); i++ {

		mibs := (*MIB_UDP6ROW_OWNER_PID)(unsafe.Pointer(&buf[index]))
		ns := NetStat{
			LocalAddr: parseIPv6(mibs.UcLocalAddr),
			LocalPort: decodePort(mibs.DwLocalPort),
			OwningPid: int(mibs.DwOwningPid),
			State:     TCPStatuses[2],
		}
		stats = append(stats, ns)

		index += step
	}
	return stats, nil
}
