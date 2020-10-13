package stanislav

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	_ "github.com/google/gopacket/layers" //Used to init internal struct
	"github.com/oschwald/geoip2-golang"
	"log"
	"net"
	"stanislav/pkg/ja3"
	"stanislav/pkg/portbitmap"
)

var myIPs = make([]net.IP, 0, 2)
var topCountryVisit = make(map[string]int)

func (p *Peng) inspect(packet gopacket.Packet) {
	var ipv4Layer gopacket.Layer //skip inspection if i can't obtain ip layer
	if ipv4Layer = packet.Layer(layers.LayerTypeIPv4); ipv4Layer == nil {
		return
	}

	ipv4, _ := ipv4Layer.(*layers.IPv4)
	var packetDestToMyPc bool
	for _, ip := range myIPs {
		if ipv4.SrcIP.Equal(ip) {
			break
		}
		if !packetDestToMyPc && ipv4.DstIP.Equal(ip) {
			packetDestToMyPc = true
			break
		}
	}

	externalIp := ipv4.DstIP.String()
	if packetDestToMyPc {
		externalIp = ipv4.SrcIP.String()
	}

	//Port scanning check
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)

		if tcp.SYN && !tcp.ACK {
			p.PortScanningHandler(uint16(tcp.DstPort), packetDestToMyPc)

			if p.Config.Verbose == 3 {
				if packetDestToMyPc {
					logger.Printf("server traffic: %s \n", tcp.DstPort.String())
				} else {
					logger.Printf("client traffic: %s \n", tcp.DstPort.String())
				}
			}
		}
	}

	GeoIpSearch(externalIp, p.Config.GeoIpDb)

	//BLACKLISTED c2 Server
	if name, ok := blackListIp[externalIp]; ok {
		AddPossibleThreat(externalIp, "c2 server " + name)
		logger.Printf("[%s] appears in the blocked c2 list as %s!\n", externalIp, name)
	}

	externalIp = ipv4.SrcIP.String() + "/" + ipv4.DstIP.String() //TODO

	if len(ja3BlackList) != 0 {
		ja3.Security = 0
		ja3md5 := ja3.DigestHexPacket(packet) //TODO replace this in the previous tcp handler
		ja3smd5 := ja3.DigestHexPacketJa3s(packet)

		if p.Config.Verbose == 2 {
			if ja3md5 != "" {
				logger.Printf("J:  %s\n", ja3md5)
			}
			if ja3smd5 != "" {
				logger.Printf("JS: %s\n", ja3smd5)
			}
		}
		//TODO improvmenet external IP detection, especially in offline mode! Maybe loading a filtering list
		if name, ok := ja3BlackList[ja3md5]; ok {
			AddPossibleThreat(externalIp, "ja3 blocklist "+name)
			logger.Printf("[%s] %s appears in the blocked Ja3 list as %s!\n", externalIp, ja3md5, name)
		}
		if name, ok := ja3BlackList[ja3smd5]; ok {
			AddPossibleThreat(externalIp, "ja3s blocklist "+name)
			logger.Printf("[%s] %s appears in the blocked Ja3 list as %s!\n", externalIp, ja3smd5, name)
		}


		//TODO add TLS version check
		//TLS cipher security check
		switch ja3.Security {
		case 1:
			AddPossibleThreat(externalIp, "Weak tls cipher")
			logger.Println("Weak tls cipher")
		case 2:
			AddPossibleThreat(externalIp, "Insecure tls cipher")
			logger.Println("Insecure tls cipher")
		}
	}

	//TODO add http numeric ip

}

func GeoIpSearch(ip, dbPath string) {
	db, err := geoip2.Open(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	parsedIp := net.ParseIP(ip)
	record, err := db.Country(parsedIp)
	if err != nil {
		logger.Println(err)
	}

	if record.Country.IsoCode != "" {
		//fmt.Printf("[%s] nation: %s \n", ip, record.Country.IsoCode)
		topCountryVisit[record.Country.IsoCode]++
	}
}

func (p *Peng) PortScanningHandler(port uint16, incomingPck bool) {
	if incomingPck {
		addPortToBitmap(port, p.ServerTraffic)
	} else {
		addPortToBitmap(port, p.ClientTraffic)
	}
}

func addPortToBitmap(port uint16, pBitmap *portbitmap.PortBitmap) {
	err := pBitmap.AddPort(port)
	if err != nil {
		logger.Println(err.Error())
	}
}

func getMyIp() {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		logger.Fatal(err.Error())
	}

	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				myIPs = append(myIPs, ipnet.IP)
			}
		}
	}
}
