package stanislav

import (
	"flag"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"
)

var (
	IpAddrNF            = ""
	PortNF              = "2055"
	Tolerance           = 10.0 //10%
	NTwToCompare        = 3
	FlowPath            = "/tmp/2020" //./flows
	analisi             = AllFlows{}
	PeriodiFlows        = PeriodicFlows{}
	opts                *Options
	Conf                *Config
	logger              *log.Logger
	PercentageDeviation = 5.0
	blackListIp         = make(map[string]string)
)

var (
	version    string
	maxWorkers = runtime.NumCPU() * 1e4
)

// Options represents options
type Options struct {
	// global options
	Verbosity bool
	CPUCap    string `yaml:"cpu-cap"`
	Logger    *log.Logger
	version   bool

	// Netflow
	NetflowV9Enabled      bool   `yaml:"netflow9-enabled"`
	NetflowV9Port         int    `yaml:"netflow9-port"`
	NetflowV9UDPSize      int    `yaml:"netflow9-udp-size"`
	NetflowV9Workers      int    `yaml:"netflow9-workers"`
	NetflowV9Topic        string `yaml:"netflow9-topic"`
	NetflowV9TplCacheFile string `yaml:"netflow9-tpl-cache-file"`
}

func init() {
	if version == "" {
		version = "unknown"
	}
}

// NewOptions constructs new options
func NewOptions() *Options {
	return &Options{
		Verbosity: false,
		version:   false,
		CPUCap:    "100%",
		Logger:    log.New(os.Stderr, "[LOG] ", log.Ldate|log.Ltime),

		NetflowV9Enabled:      true,
		NetflowV9Port:         2055,
		NetflowV9UDPSize:      1500,
		NetflowV9Workers:      1,
		NetflowV9Topic:        "vflow.netflow9",
		NetflowV9TplCacheFile: "/tmp/netflowv9.templates",
	}
}

// GetOptions gets options through cmd and file
func GetOptions() *Options {
	opts := NewOptions()

	//opts.flagSet()

	if opts.Verbosity {
		opts.Logger.Printf("the full logging enabled")
		opts.Logger.SetFlags(log.LstdFlags | log.Lshortfile)
	}

	return opts
}

// getCPU returns the number of the CPU
func (opts Options) getCPU() int {
	var (
		numCPU      int
		availCPU    = runtime.NumCPU()
		invalCPUErr = "the CPU percentage is invalid: it should be between 1-100"
		numCPUErr   = "the CPU number should be greater than zero!"
	)

	if strings.Contains(opts.CPUCap, "%") {
		pctStr := strings.Trim(opts.CPUCap, "%")

		pctInt, err := strconv.Atoi(pctStr)
		if err != nil {
			opts.Logger.Fatalf("invalid CPU cap")
		}

		if pctInt < 1 || pctInt > 100 {
			opts.Logger.Fatalf(invalCPUErr)
		}

		numCPU = int(float32(availCPU) * (float32(pctInt) / 100))
	} else {
		numInt, err := strconv.Atoi(opts.CPUCap)
		if err != nil {
			opts.Logger.Fatalf("invalid CPU cap")
		}

		if numInt < 1 {
			opts.Logger.Fatalf(numCPUErr)
		}

		numCPU = numInt
	}

	if numCPU > availCPU {
		numCPU = availCPU
	}

	return numCPU
}

func (opts *Options) flagSet() {
	var config string
	flag.StringVar(&config, "config", "/etc/vflow/vflow.conf", "path to config file")

	// global options
	flag.BoolVar(&opts.Verbosity, "verbosity", opts.Verbosity, "enable/disable verbose logging")
	flag.BoolVar(&opts.version, "version", opts.version, "show version")
	flag.StringVar(&opts.CPUCap, "cpu-cap", opts.CPUCap, "Maximum amount of CPU [percent / number]")

	// netflow version 9
	flag.BoolVar(&opts.NetflowV9Enabled, "netflow9-enabled", opts.NetflowV9Enabled, "enable/disable netflow version 9 listener")
	flag.IntVar(&opts.NetflowV9Port, "netflow9-port", opts.NetflowV9Port, "Netflow Version 9 port number")
	flag.IntVar(&opts.NetflowV9UDPSize, "netflow9-max-udp-size", opts.NetflowV9UDPSize, "Netflow version 9 maximum UDP size")
	flag.IntVar(&opts.NetflowV9Workers, "netflow9-workers", opts.NetflowV9Workers, "Netflow version 9 workers number")
	flag.StringVar(&opts.NetflowV9Topic, "netflow9-topic", opts.NetflowV9Topic, "Netflow version 9 topic name")
	flag.StringVar(&opts.NetflowV9TplCacheFile, "netflow9-tpl-cache-file", opts.NetflowV9TplCacheFile, "Netflow version 9 template cache file")

	flag.Usage = func() {
		flag.PrintDefaults()
	}

	flag.Parse()
}
