package main

//TODO add support for ipv6, netflow5 and IPFX
import (
	"flag"
	"fmt"
	"stanislav"
	"time"
)

func init() {
	flag.StringVar(&stanislav.FlowPath, "flowPath", "", "dir path to load flows of nProbe")
	flag.Float64Var(&stanislav.Tolerance, "tolerance", 10, "maximum % tolerance before flag possible periodic flow.")
	flag.IntVar(&stanislav.NTwToCompare, "nCompare", 3, "number o time windows to compare to evaluate a possible periodicity")
	flag.StringVar(&stanislav.IpAddrNF, "ip", "", "ip of netflow collector")
	flag.StringVar(&stanislav.PortNF, "port", "2055", "port of netflow collector")
	flag.IntVar(&stanislav.Verbose, "verbose", 0, "verbosity level. (1=low,2=medium,3=high")
}

func flagConfig() {
	flag.Usage = func() { //help flag
		fmt.Fprintf(flag.CommandLine.Output(), "\n\nUsage: flow-periodicity [options]\n")
		flag.PrintDefaults()
	}

	flag.Parse()
	stanislav.PercentageDeviation = stanislav.Tolerance //TODO refactor this
	//TODO add check for ip and port
	//TODO add check for tolerance 0 <= tolerance <= 100
}

func main() {
	flagConfig()

	if stanislav.FlowPath != "" {
		stanislav.OfflineMode()
		FlowStats()
		stanislav.WriteObjToJSONFile(time.Now().Format(time.RFC3339)+"_report.json", stanislav.PeriodiFlows)
		return
	}

	stanislav.LiveMode()
	FlowStats()
	stanislav.WriteObjToJSONFile(time.Now().Format(time.RFC3339)+"_report.json", stanislav.PeriodiFlows)
}

func FlowStats() {
	json, err := stanislav.PeriodiFlows.Marshal()
	if err != nil {
		return
	}
	fmt.Printf("%s", string(json))
}
