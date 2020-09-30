package periodicity

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	netflow9 "github.com/VerizonDigital/vflow/netflow/v9"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

func WalkAllDirs(basepath string) []string {
	dirs := make([]string, 0, 100)
	err := filepath.Walk(basepath,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() {
				dirs = append(dirs, path)
			}
			return nil
		})

	if err != nil {
		log.Println(err)
	}
	return dirs
}

func ConvStringToDate(input string) (time.Time, error) {
	v, err := strconv.ParseInt(input, 10, 64)
	if err != nil {
		return time.Time{}, err
	}

	return time.Unix(v, 0), nil
}

func GetAbsDateNF9(input string, ph netflow9.PacketHeader) (time.Time, error) {
	vt, err := time.ParseDuration(input + "ms")
	if err != nil {
		return time.Time{}, err
	}

	sysUpTime, err := time.ParseDuration(fmt.Sprint(ph.SysUpTime) + "ms")
	if err != nil {
		return time.Time{}, err
	}

	t := time.Unix(int64(ph.UNIXSecs), 0)
	t = t.Add(-sysUpTime + vt)
	return t, nil
}

func IsMulticastAddress(ip string) bool {
	return net.ParseIP(ip).IsMulticast()
}

func IsBroadcastAddress(ip string) bool {
	addr := net.ParseIP(ip)
	netIp := net.IPNet{
		IP:   addr,
		Mask: addr.DefaultMask(),
	}
	lastAddr, err := lastAddr(&netIp)
	if err != nil {
		return false
	}
	return addr.Equal(lastAddr)
}

func lastAddr(n *net.IPNet) (net.IP, error) { // works when the n is a prefix, otherwise...
	if n.IP.To4() == nil {
		return net.IP{}, errors.New("does not support IPv6 addresses")
	}
	ip := make(net.IP, len(n.IP.To4()))
	binary.BigEndian.PutUint32(ip, binary.BigEndian.Uint32(n.IP.To4())|^binary.BigEndian.Uint32(net.IP(n.Mask).To4()))
	return ip, nil
}

func DEBUG(v RawFlow, ip, tempo string) {
	if v.Ipv4DstAddr == ip {
		fmt.Printf("%v ", tempo)
	}
}

func ConvFloatToDuration(v float64) time.Duration {
	xTime, err := time.ParseDuration(fmt.Sprint(v, "s"))
	if err != nil {
		return time.Second
	}

	return xTime
}

func WriteObjToJSONFile(fname string, obj interface{}) {
	if _, err := os.Stat("./dump"); os.IsNotExist(err) {
		os.Mkdir("./dump", os.ModePerm)
	}

	file, _ := os.OpenFile("./dump/"+fname, os.O_CREATE|os.O_RDWR, os.ModePerm)
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.Encode(obj)
}
