package main

//TODO add support for ipv6, netflow5 and IPFX
import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/google/gopacket/pcap"
	"log"
	"net/url"
	"os"
	"stanislav"
	"time"
)

var (
	config = stanislav.Config{
		NumberOfBin:        128,
		SizeBitmap:         1024,
		InfluxUrl:          "http://localhost",
		InfluxPort:         9999,
		InfluxBucket:       "",
		InfluxOrganization: "",
		InfluxAuthToken:    "",
		SaveFilePath:       "",
		UseInflux:          false,
		Verbose:            uint(0),
		NetworkInterface:   "",
		Ja3BlackListFile:   "",
		GeoIpDb:            "",
		OfflinePcap:        "",
	}
	timeFrame = "15s"

	showInterfaceNames bool
	versionFlag        bool
	version            = "0.0.0"
	commit             = "commithash"
)

func init() {
	//NetFlow
	flag.StringVar(&stanislav.FlowPath, "flowPath", "", "dir path to load flows of nProbe")
	flag.Float64Var(&stanislav.Tolerance, "tolerance", 10, "maximum % tolerance before flag possible periodic flow.")
	flag.IntVar(&stanislav.NTwToCompare, "nCompare", 3, "number o time windows to compare to evaluate a possible periodicity")
	flag.StringVar(&stanislav.IpAddrNF, "ip", "", "ip of netflow collector")
	flag.StringVar(&stanislav.PortNF, "port", "2055", "port of netflow collector")
	flag.IntVar(&stanislav.Verbose, "verbose", 0, "verbosity level. (1=low,2=medium,3=high")

	//Bitmap
	flag.UintVar(&config.NumberOfBin, "bin", 16, "number of bin in your bitmap")
	flag.UintVar(&config.SizeBitmap, "size", 1024, "size of your bitmap")

	//influx
	flag.StringVar(&config.InfluxUrl, "influxUrl", "http://localhost", "influx url")
	flag.UintVar(&config.InfluxPort, "influxPort", 9999, "influxPort number")
	flag.StringVar(&config.InfluxBucket, "bucket", "", "bucket string for telegraf")
	flag.StringVar(&config.InfluxOrganization, "org", "", "organization string for telegraf")
	flag.StringVar(&config.InfluxAuthToken, "token", "", "auth token for influxdb")

	//other
	flag.BoolVar(&versionFlag, "version", false, "output version")
	flag.StringVar(&config.SaveFilePath, "export", "", "file path to save the peng result as csv")
	flag.StringVar(&timeFrame, "timeFrame", "15s", "interval time to detect scans. Number + (s = seconds, m = minutes, h = hours)")
	flag.StringVar(&config.NetworkInterface, "network", "", "name of your network interface")
	flag.BoolVar(&showInterfaceNames, "interfaces", false, "show the list of all your network interfaces")
	flag.StringVar(&config.Ja3BlackListFile, "ja3", "", "file path of malicious ja3 fingerprints")
	flag.StringVar(&config.GeoIpDb, "geoip", "", "file path of geoip db")
	flag.StringVar(&config.OfflinePcap, "pcap", "", "pcap file to read")
}

func flagConfig() {
	appString := fmt.Sprintf("________                     \n___  __ \\__________________ _\n__  /_/ /  _ \\_  __ \\_  __ `/\n_  ____//  __/  / / /  /_/ / \n/_/     \\___//_/ /_/_\\__, /  \n                    /____/   \n"+
		"version %s %s", version, commit)

	flag.Usage = func() { //help flag
		fmt.Fprintf(flag.CommandLine.Output(), "\n\nUsage: flow-periodicity [options]\n")
		flag.PrintDefaults()
	}

	flag.Parse()
	stanislav.PercentageDeviation = stanislav.Tolerance //TODO refactor this
	//TODO add check for ip and port
	//TODO add check for tolerance 0 <= tolerance <= 100

	if versionFlag { //version flag
		fmt.Fprintf(flag.CommandLine.Output(), "%s\n", appString)
		os.Exit(2)
	}

	if showInterfaceNames {
		interfaces, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatal(err.Error())
		}
		for _, v := range interfaces {
			fmt.Printf("name: \"%s\"\n\t %s %s %d \n", v.Name, v.Description, v.Addresses, v.Flags)
		}
		os.Exit(2)
	}

	if config.NetworkInterface == "" {
		log.Fatal("You must provide the device adapter you want to listen to")
	}

	if config.InfluxAuthToken != "" && config.InfluxBucket == "" && config.InfluxOrganization == "" {
		log.Fatal("You must provide bucket, organization and influxAuthToken")
	}

	if _, err := url.ParseRequestURI(config.InfluxUrl); err != nil {
		log.Fatal("Influx url is not valid")
	}

	if config.InfluxAuthToken == "" && config.SaveFilePath == "" && config.Verbose == 0 {
		log.Fatal("You must provide at least 1 method to send or display the data")
	}

	//Check timeFrame input to perform port scan detection
	if v, err := time.ParseDuration(timeFrame); err != nil {
		log.Fatal("Invalid interval format.")
	} else if v.Seconds() <= 0 {
		log.Fatal("Interval too short it must be at least 1 second long")
	} else {
		config.TimeFrame = v
	}

	//check if user exceed maximum allowed verbosity
	if config.Verbose > 3 {
		config.Verbose = 3
	}

	if config.SizeBitmap > 1<<16 {
		log.Fatal("Size of full bitmap is too big, it must be less than 65536")
	}

	fmt.Printf("%s\n", appString)
}

func main() {
	flagConfig()

	if stanislav.FlowPath != "" {
		stanislav.OfflineMode()
		FlowStats()
		stanislav.WriteObjToJSONFile(time.Now().Format(time.RFC3339)+"_report.json", stanislav.PeriodiFlows)
		return
	}

	stanislav.Conf = &config //TODO handle nil
	stanislav.LiveMode()

	ThreatStats()
	FlowStats()

	stanislav.WriteObjToJSONFile(time.Now().Format(time.RFC3339)+"_report.json", stanislav.PeriodiFlows) //TODO change this like peng that every X sec dump
}

func ThreatStats() {
	fmt.Println("\nTHREAT")
	threatJson, _ := json.Marshal(stanislav.PossibleThreat)
	fmt.Println(string(threatJson))
}

func FlowStats() {
	fmt.Println("\nPeriodic flows")
	json, err := stanislav.PeriodiFlows.Marshal()
	if err != nil {
		return
	}
	fmt.Printf("%s", string(json))
}
