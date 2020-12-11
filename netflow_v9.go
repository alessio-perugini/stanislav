package stanislav

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/VerizonDigital/vflow/netflow/v9"
)

// NetflowV9 represents netflow v9 collector
type NetflowV9 struct {
	port    int
	addr    string
	workers int
	stop    bool
	stats   NetflowV9Stats
	pool    chan chan struct{}
}

// NetflowV9UDPMsg represents netflow v9 UDP data
type NetflowV9UDPMsg struct {
	raddr *net.UDPAddr
	body  []byte
}

// NetflowV9Stats represents netflow v9 stats
type NetflowV9Stats struct {
	Workers int32
}

var (
	netflowV9UDPCh = make(chan NetflowV9UDPMsg, 1000)
	netflowV9MQCh  = make(chan []byte, 1000)

	mCacheNF9 netflow9.MemCache

	// ipfix udp payload pool
	netflowV9Buffer = &sync.Pool{
		New: func() interface{} {
			return make([]byte, opts.NetflowV9UDPSize)
		},
	}
)

// NewNetflowV9 constructs NetflowV9
func NewNetflowV9() *NetflowV9 {
	port, err := strconv.Atoi(PortNF)
	if err != nil {
		// handle error
		port = 2055
		fmt.Println(err)
	}

	return &NetflowV9{
		port:    port, // opts.NetflowV9Port,
		addr:    IpAddrNF,
		workers: opts.NetflowV9Workers,
		pool:    make(chan chan struct{}, maxWorkers),
	}
}

func (i *NetflowV9) run() {
	if !opts.NetflowV9Enabled {
		logger.Println("netflowv9 has been disabled")
		return
	}

	hostPort := net.JoinHostPort(i.addr, strconv.Itoa(i.port))
	udpAddr, _ := net.ResolveUDPAddr("udp", hostPort)

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		logger.Fatal(err)
	}

	atomic.AddInt32(&i.stats.Workers, int32(i.workers))
	for n := 0; n < i.workers; n++ {
		go func() {
			wQuit := make(chan struct{})
			i.pool <- wQuit
			i.netflowV9Worker(wQuit)
		}()
	}

	logger.Printf("netflow v9 is running (UDP: listening on [::]:%d workers#: %d)", i.port, i.workers)

	mCacheNF9 = netflow9.GetCache(opts.NetflowV9TplCacheFile)

	for !i.stop {
		b := netflowV9Buffer.Get().([]byte)
		conn.SetReadDeadline(time.Now().Add(1e9))
		n, raddr, err := conn.ReadFromUDP(b)
		if err != nil {
			continue
		}
		netflowV9UDPCh <- NetflowV9UDPMsg{raddr, b[:n]}
	}

}

func (i *NetflowV9) shutdown() {
	// exit if the netflow v9 is disabled
	if !opts.NetflowV9Enabled {
		logger.Println("netflow v9 disabled")
		return
	}

	// stop reading from UDP listener
	i.stop = true
	logger.Println("stopping netflow v9 service gracefully ...")
	time.Sleep(1 * time.Second)

	// dump_dataset the templates to storage
	if err := mCacheNF9.Dump(opts.NetflowV9TplCacheFile); err != nil {
		logger.Println("couldn't not dump_dataset template", err)
	}

	// logging and close UDP channel
	logger.Println("netflow v9 has been shutdown")
	close(netflowV9UDPCh)
}

func (i *NetflowV9) netflowV9Worker(wQuit chan struct{}) {
	var (
		decodedMsg *netflow9.Message
		msg        = NetflowV9UDPMsg{body: netflowV9Buffer.Get().([]byte)}
		buf        = new(bytes.Buffer)
		err        error
		ok         bool
	)

LOOP:
	for {
		netflowV9Buffer.Put(msg.body[:opts.NetflowV9UDPSize])
		buf.Reset()

		select {
		case <-wQuit:
			break LOOP
		case msg, ok = <-netflowV9UDPCh:
			if !ok {
				break LOOP
			}
		}

		if opts.Verbosity {
			logger.Printf("rcvd netflow v9 data from: %s, size: %d bytes",
				msg.raddr, len(msg.body))
		}

		d := netflow9.NewDecoder(msg.raddr.IP, msg.body)
		if decodedMsg, err = d.Decode(mCacheNF9); err != nil {
			logger.Println(err)
			if decodedMsg == nil {
				continue
			}
		}

		if decodedMsg.DataSets != nil {
			for _, ds := range decodedMsg.DataSets {
				rawFlow := RawFlow{}
				//srcMask, dstMask := 0, 0
				for _, dr := range ds {
					value := fmt.Sprintf("%v", dr.Value)

					switch dr.ID {
					case 7:
						prt, err := strconv.Atoi(value)
						if err != nil {
							continue
						}
						rawFlow.PortSrc = uint16(prt)
					case 8:
						rawFlow.Ipv4SrcAddr = value
					case 9:
						/*v, err := strconv.Atoi(value)
						if err != nil {
							continue
						}
						srcMask = v*/
					case 11:
						prt, err := strconv.Atoi(value)
						if err != nil {
							continue
						}
						rawFlow.PortDst = uint16(prt)
					case 12:
						rawFlow.Ipv4DstAddr = value
					case 13:
						/*v, err := strconv.Atoi(value)
						if err != nil {
							continue
						}
						dstMask = v*/
					case 21:
						t, err := GetAbsDateNF9(value, decodedMsg.Header)
						if err != nil {
							continue
						}
						rawFlow.LastSwitched = t

					case 22:
						t, err := GetAbsDateNF9(value, decodedMsg.Header)
						if err != nil {
							continue
						}

						rawFlow.FirstSwitched = t
					case 61: //[1=src->dst, 0=dst->src]
						direction, err := strconv.Atoi(value)
						if err != nil {
							continue
						}
						rawFlow.Direction = uint(direction)
					case 136:
						end, err := strconv.Atoi(value)
						if err != nil {
							continue
						}
						rawFlow.EndReason = uint8(end)
					case 239: //%BIFLOW_DIRECTION 1=initiator, 2=reverseInitiator
						direction, err := strconv.Atoi(value)
						if err != nil {
							continue
						}
						rawFlow.BiFlowDirection = uint(direction)
					case 57677: //DNS query
						fmt.Println()
					case 57981:
						fmt.Println()
					}
				} /*
					if srcMask > 0 && dstMask > 0 {
						fmt.Println(srcMask, " ", dstMask)
					}*/
				InspectFlow(rawFlow)
			}
		}
	}
}
