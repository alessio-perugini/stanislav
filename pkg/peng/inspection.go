package peng

import (
	"fmt"
	"github.com/alessio-perugini/peng/pkg/portbitmap"
	"github.com/dreadl0ck/ja3"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	_ "github.com/google/gopacket/layers" //Used to init internal struct
	"log"
	"net"
	"time"
)

var myIPs = make([]net.IP, 0, 2)

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
	//TODO add blacklist check
	ja3string := ja3.DigestHexPacket(packet)
	ja3sstring := ja3.DigestHexPacketJa3s(packet)
	if p.Config.Verbose == 2 {
		if ja3string != "" {
			fmt.Printf("J1: %s\n", ja3string)
		}
		if ja3sstring != "" {
			fmt.Printf("J2: %s\n", ja3sstring)
		}
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