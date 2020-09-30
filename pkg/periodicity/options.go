package periodicity

import (
	"flag"
	"fmt"
	"log"
	"os"
	"reflect"
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
	logger              *log.Logger
	PercentageDeviation = 5.0
	Verbose             = 0
)

var (
	version    string
	maxWorkers = runtime.NumCPU() * 1e4
)

type arrUInt32Flags []uint32

// Options represents options
type Options struct {
	// global options
	Verbosity bool
	LogFile   string `yaml:"log-file"`
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

func (a *arrUInt32Flags) String() string {
	return "SFlow Type string"
}

func (a *arrUInt32Flags) Set(value string) error {
	arr := strings.Split(value, ",")
	for _, v := range arr {
		v64, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return err
		}
		*a = append(*a, uint32(v64))
	}

	return nil
}

// NewOptions constructs new options
func NewOptions() *Options {
	return &Options{
		Verbosity: true,
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

	opts.flagSet()

	if opts.Verbosity {
		opts.Logger.Printf("the full logging enabled")
		opts.Logger.SetFlags(log.LstdFlags | log.Lshortfile)
	}

	if opts.LogFile != "" {
		f, err := os.OpenFile(opts.LogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			opts.Logger.Println(err)
		} else {
			opts.Logger.SetOutput(f)
		}
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

	opts.getEnv()
	//opts.loadCfg()

	// global options
	flag.BoolVar(&opts.Verbosity, "verbosity", opts.Verbosity, "enable/disable verbose logging")
	flag.BoolVar(&opts.version, "version", opts.version, "show version")
	flag.StringVar(&opts.LogFile, "log-file", opts.LogFile, "log file name")
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
		fmt.Fprintf(os.Stderr, `
    Example:
	# set workers
	vflow -sflow-workers 15 -ipfix-workers 20
	# set 3rd party ipfix collector
	vflow -ipfix-mirror-addr 192.168.1.10 -ipfix-mirror-port 4319
	# enaable verbose logging
	vflow -verbose=true
	# for more information
	https://github.com/VerizonDigital/vflow/blob/master/docs/config.md
    `)

	}

	flag.Parse()
}

func (opts *Options) getEnv() {
	r := reflect.TypeOf(*opts)
	for i := 0; i < r.NumField(); i++ {
		key := strings.ToUpper(r.Field(i).Tag.Get("yaml"))
		key = strings.ReplaceAll(key, "-", "_")
		key = fmt.Sprintf("VFLOW_%s", key)
		value := os.Getenv(key)

		ve := reflect.ValueOf(opts).Elem()
		if value != "" {
			switch ve.Field(i).Kind() {
			case reflect.String:
				ve.Field(i).SetString(value)
			case reflect.Int:
				v, err := strconv.Atoi(value)
				if err != nil {
					log.Fatal(err)
					return
				}
				ve.Field(i).SetInt(int64(v))
			case reflect.Bool:
				v, err := strconv.ParseBool(value)
				if err != nil {
					log.Fatal(err)
					return
				}
				ve.Field(i).SetBool(v)
			}

		}
	}
}
