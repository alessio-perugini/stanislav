package stanislav

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/google/gopacket"
	_ "github.com/google/gopacket/layers" //Used to init internal struct
	"github.com/google/gopacket/pcap"
	"os"
	"stanislav/pkg/portbitmap"
	"time"
)

type Peng struct {
	Config                       *Config
	ClientTraffic, ServerTraffic *portbitmap.PortBitmap
	stop                         bool
}

type Config struct {
	NumberOfBin        uint
	SizeBitmap         uint
	NumberOfBits       uint
	SaveFilePath       string
	NetworkInterface   string
	UseInflux          bool
	InfluxUrl          string
	InfluxPort         uint
	InfluxBucket       string
	InfluxOrganization string
	InfluxAuthToken    string
	Verbose            uint
	TimeFrame          time.Duration
	Ja3BlackListFile   string
	GeoIpDb            string
	OfflinePcap        string
	IpBlackListFile    string
}

var ja3BlackList map[string]string

func New(cfg *Config) *Peng {
	cfg.NumberOfBits = cfg.SizeBitmap / cfg.NumberOfBin
	bitmapConfig := &portbitmap.Config{
		NumberOfBin:  cfg.NumberOfBin,
		SizeBitmap:   cfg.SizeBitmap,
		NumberOfBits: cfg.NumberOfBits,
	}
	var peng = Peng{
		Config:        cfg,
		ClientTraffic: portbitmap.New(bitmapConfig),
		ServerTraffic: portbitmap.New(bitmapConfig),
	}

	return &peng
}

func (p *Peng) run() {
	getMyIp()
	p.LoadBlackListJa3InMemory()
	var pHandle *pcap.Handle
	var err error

	if p.Config.OfflinePcap == "" {
		pHandle, err = pcap.OpenLive(
			p.Config.NetworkInterface,
			int32(65535),
			false,
			pcap.BlockForever)
	} else {
		pHandle, err = pcap.OpenOffline(p.Config.OfflinePcap)
	}

	if err != nil {
		logger.Fatal(err)
	}
	defer pHandle.Close()

	packet := gopacket.NewPacketSource(pHandle, pHandle.LinkType())

	timer := time.AfterFunc(p.Config.TimeFrame, p.handler)

	start := time.Now()
	for packet := range packet.Packets() {
		if p.stop { //TODO forse passare il puntatore di peng
			timer.Stop()
			return
		}
		p.inspect(packet)
	}
	fmt.Println("Durata: ", time.Now().Sub(start).Seconds())
}

func (p *Peng) shutdown() {
	p.stop = true
	logger.Println("stopping peng module...")
	time.Sleep(1 * time.Second)

	//TODO
	logger.Println("\n\nTOP COUNTRY VISIT")
	threatJson, _ := json.Marshal(topCountryVisit)
	fmt.Println(string(threatJson))
}

func (p *Peng) LoadBlackListJa3InMemory() {
	file, err := os.OpenFile(p.Config.Ja3BlackListFile, os.O_RDONLY, 0777)
	defer file.Close()

	if err != nil {
		logger.Println(err)
		return
	}

	r := csv.NewReader(file)
	ja3BlackList = make(map[string]string)
	r.Comment = '#'
	for {
		csvField, err := r.Read()
		if err != nil {
			break
		}

		//Parse csv fields
		md5h := csvField[0] //md5 hash
		name := csvField[3] //malware name

		ja3BlackList[md5h] = name
	}
}

func (p *Peng) PrintAllInfo() {
	allPortTraffic := []*portbitmap.PortBitmap{p.ClientTraffic, p.ServerTraffic}
	for i, v := range allPortTraffic {
		if p.Config.Verbose == 3 {
			logger.Println(v) //Print all bitmap
			logger.Println("Bit set: ")
			for i := 0; i < len(v.InnerBitmap); i++ {
				logger.Println("bin number [", i, "]    num (bit at 1): ", v.InnerBitmap[i].GetBitSets())
			}
		}
		if p.Config.Verbose >= 1 {
			if i == 0 {
				logger.Printf("[CLIENT] ")
			} else {
				logger.Printf("[SERVER] ")
			}
		}
		if p.Config.Verbose >= 2 {
			logger.Printf("entropy of each bin: %f\n", v.EntropyOfEachBin())
		}

		totalEntropy := v.EntropyTotal()
		if totalEntropy >= 0.5 {
			AddPossibleThreat("general", fmt.Sprintf("probably a port scan. Total entropy: %.2f", totalEntropy))
			logger.Printf("possible port scan. Total entropy: %.2f", totalEntropy)
		}
		if p.Config.Verbose >= 1 {
			logger.Printf("total entropy: %f\n", totalEntropy)
		}
	}
}

func (p *Peng) handler() {
	p.PushToInfluxDb()
	p.ExportToCsv()

	p.PrintAllInfo()

	//Clear bitmap for the new reader
	p.ClientTraffic.ClearAll()
	p.ServerTraffic.ClearAll()

	if p.stop {
		return
	}
	//Wait timeframe time, before further actions
	time.AfterFunc(p.Config.TimeFrame, p.handler)
}
