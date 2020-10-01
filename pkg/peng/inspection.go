package peng

import (
	"fmt"
	"github.com/dreadl0ck/ja3"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	_ "github.com/google/gopacket/layers" //Used to init internal struct
	"github.com/oschwald/geoip2-golang"
	"log"
	"net"
	"stanislav/pkg/portbitmap"
	"time"
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

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)

		if tcp.SYN && !tcp.ACK {
			p.PortScanningHandler(uint16(tcp.DstPort), packetDestToMyPc)

			if p.Config.Verbose == 3 {
				if packetDestToMyPc {
					fmt.Printf("[%s] server traffic: %s \n", time.Now().Local().String(), tcp.DstPort.String())
				} else {
					fmt.Printf("[%s] client traffic: %s \n", time.Now().Local().String(), tcp.DstPort.String())
				}
			}
		}
	}

	/*
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)

			totalSize := udp.Length
			payloadSize := len(udp.Payload)
			goodput := totalSize - uint16(payloadSize)

			if
		}*/

	externalIp := ipv4.DstIP.String()
	if packetDestToMyPc {
		externalIp = ipv4.SrcIP.String()
	}

	GeoIpSearch(externalIp, p.Config.GeoIpDb)

	if len(ja3BlackList) != 0 {
		ja3.Security = 0
		ja3md5 := ja3.DigestHexPacket(packet) //TODO replace this in the previous tcp handler
		ja3smd5 := ja3.DigestHexPacketJa3s(packet)

		if p.Config.Verbose == 2 {
			if ja3md5 != "" {
				fmt.Printf("J:  %s\n", ja3md5)
			}
			if ja3smd5 != "" {
				fmt.Printf("JS: %s\n", ja3smd5)
			}
		}

		if name, ok := ja3BlackList[ja3md5]; ok {
			fmt.Printf("[%s] %s appears in the blocked Ja3 list as %s!\n", externalIp, ja3md5, name)
		}
		if name, ok := ja3BlackList[ja3smd5]; ok {
			fmt.Printf("[%s] %s appears in the blocked Ja3 list as %s!\n", externalIp, ja3smd5, name)
		}

		//TODO add TLS version check
		//TLS cipher security check
		switch ja3.Security {
		case 1:
			fmt.Println("Weak tls cipher")
		case 2:
			fmt.Println("Insecure tls cipher")
		}
	}
	//				switch hello.CipherSuite {
	//				case 49169: fallthrough /* TLS_ECDHE_RSA_WITH_RC4_128_SHA */
	//				case 5: fallthrough /* TLS_RSA_WITH_RC4_128_SHA */
	//				case 4:  Security = 2 /* TLS_RSA_WITH_RC4_128_MD5 */
	//					/* WEAK */
	//				case 157: fallthrough /* TLS_RSA_WITH_AES_256_GCM_SHA384 */
	//				case 61: fallthrough /* TLS_RSA_WITH_AES_256_CBC_SHA256 */
	//				case 53: fallthrough /* TLS_RSA_WITH_AES_256_CBC_SHA */
	//				case 132: fallthrough /* TLS_RSA_WITH_CAMELLIA_256_CBC_SHA */
	//				case 156: fallthrough /* TLS_RSA_WITH_AES_128_GCM_SHA256 */
	//				case 60: fallthrough /* TLS_RSA_WITH_AES_128_CBC_SHA256 */
	//				case 47: fallthrough /* TLS_RSA_WITH_AES_128_CBC_SHA */
	//				case 65: fallthrough /* TLS_RSA_WITH_CAMELLIA_128_CBC_SHA */
	//				case 49170: fallthrough /* TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA */
	//				case 22: fallthrough /* TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA */
	//				case 10: fallthrough /* TLS_RSA_WITH_3DES_EDE_CBC_SHA */
	//				case 150: fallthrough /* TLS_RSA_WITH_SEED_CBC_SHA */
	//				case 7: Security = 1 /* TLS_RSA_WITH_IDEA_CBC_SHA */
	//				default:     Security = 0
	//				}
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
		log.Println(err)
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
		log.Println(err.Error())
	}
}

func getMyIp() {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Fatal(err.Error())
	}

	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				myIPs = append(myIPs, ipnet.IP)
			}
		}
	}
}
