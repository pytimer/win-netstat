package winnetstat

import (
	"fmt"
	"syscall"
)

// NetStat return a netstat record
type NetStat struct {
	LocalAddr  string
	LocalPort  uint16
	RemoteAddr string
	RemotePort uint16
	OwningPid  int
	State      string
}

// netProtoKindType ...
type netProtoKindType struct {
	family   uint32
	filename string
}

var kindTCP4 = netProtoKindType{
	family:   syscall.AF_INET,
	filename: "tcp4",
}

var kindTCP6 = netProtoKindType{
	family:   syscall.AF_INET6,
	filename: "tcp6",
}

var kindUDP4 = netProtoKindType{
	family:   syscall.AF_INET,
	filename: "udp4",
}
var kindUDP6 = netProtoKindType{
	family:   syscall.AF_INET6,
	filename: "udp6",
}

var netProtoKindMap = map[string][]netProtoKindType{
	"all":   {kindTCP4, kindTCP6, kindUDP4, kindUDP6},
	"tcp":   {kindTCP4, kindTCP6},
	"tcp4":  {kindTCP4},
	"tcp6":  {kindTCP6},
	"udp":   {kindUDP4, kindUDP6},
	"udp4":  {kindUDP4},
	"udp6":  {kindUDP6},
	"inet4": {kindTCP4, kindUDP4},
	"inet6": {kindTCP6, kindUDP6},
}

// Connections list all netstats include: tcp tcp6 udp udp6
func Connections(kind string) ([]NetStat, error) {
	return ConnectionsWithPid(kind, 0)
}

// ConnectionsWithPid list specfic pid netstats include: tcp tcp6 udp udp6
func ConnectionsWithPid(kind string, pid int) ([]NetStat, error) {
	kindMap, ok := netProtoKindMap[kind]
	if !ok {
		return nil, fmt.Errorf("invalid kind: %s", kind)
	}

	if pid == 0 {
		return getAllInetStat(kindMap)
	}

	return getProcInet(kindMap, pid)
}

func getAllInetStat(kinds []netProtoKindType) ([]NetStat, error) {
	stats := make([]NetStat, 0)
	for _, kind := range kinds {
		s, _ := getNetStatWithKindFile(kind.filename)
		stats = append(stats, s...)
	}
	return stats, nil
}

func getProcInet(kinds []netProtoKindType, pid int) ([]NetStat, error) {
	stats := make([]NetStat, 0)

	for _, kind := range kinds {
		s, err := getNetStatWithKindFile(kind.filename)
		if err != nil {
			return nil, err
		}

		for _, ns := range s {
			if ns.OwningPid != pid {
				continue
			}
			stats = append(stats, ns)
		}
	}

	return stats, nil
}

func getNetStatWithKindFile(filename string) ([]NetStat, error) {
	if filename == "" {
		return nil, fmt.Errorf("kind filename must be required")
	}

	switch filename {
	case kindTCP4.filename:
		return getTCP4Stat()
	case kindTCP6.filename:
		return getTCP6Stat()
	case kindUDP4.filename:
		return getUDP4Stat()
	case kindUDP6.filename:
		return getUDP6Stat()
	default:
		return nil, fmt.Errorf("invalid kind filename: %s", filename)
	}

	return nil, nil
}
