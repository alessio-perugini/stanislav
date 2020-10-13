package stanislav

import (
	"encoding/binary"
	"encoding/csv"
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

func AddPossibleThreat(ip, reason string) {
	if reasons, ok := PossibleThreat[ip]; ok {
		for _, v := range reasons { //avoid duplicate reasons
			if v == reason {
				return
			}
		}
		reasons = append(reasons, reason)
		PossibleThreat[ip] = reasons
	} else {
		PossibleThreat[ip] = []string{reason}
	}
}

func LoadBlockListedC2() {
	if Conf.IpBlackListFile == "" {
		logger.Println("c2 block list not selected")
		return
	}

	file, err := os.OpenFile(Conf.IpBlackListFile, os.O_RDONLY, 0777)
	defer file.Close()

	if err != nil {
		logger.Println(err)
		return
	}

	r := csv.NewReader(file)
	r.Comment = '#'

	for {
		csvField, err := r.Read()
		if err != nil {
			break
		}

		//Parse csv fields
		ip := csvField[1]   //ip
		name := csvField[4] //malware name

		blackListIp[ip] = name
	}
}

func checkAndSetPossibleThreat(blockedMap map[string]string, key, ip, reason string) {
	if name, ok := blockedMap[key]; ok {
		AddPossibleThreat(ip, reason+" "+name)
		logger.Printf("[%s] appears in the blocked list. %s!\n", ip, name)
	}
}
