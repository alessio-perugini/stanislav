package main

//TODO add support for ipv6, netflow5 and IPFX
import (
	"flag"
	"fmt"
	p "stanislav/pkg/periodicity"
	"time"
)

func init() {
	flag.StringVar(&p.FlowPath, "flowPath", "", "dir path to load flows of nProbe")
	flag.Float64Var(&p.Tolerance, "tolerance", 10, "maximum % tolerance before flag possible periodic flow.")
	flag.IntVar(&p.NTwToCompare, "nCompare", 3, "number o time windows to compare to evaluate a possible periodicity")
	flag.StringVar(&p.IpAddrNF, "ip", "", "ip of netflow collector")
	flag.StringVar(&p.PortNF, "port", "2055", "port of netflow collector")
	flag.IntVar(&p.Verbose, "verbose", 0, "verbosity level. (1=low,2=medium,3=high")
}

func flagConfig() {
	flag.Usage = func() { //help flag
		fmt.Fprintf(flag.CommandLine.Output(), "\n\nUsage: flow-periodicity [options]\n")
		flag.PrintDefaults()
	}

	flag.Parse()
	p.PercentageDeviation = p.Tolerance //TODO refactor this
	//TODO add check for ip and port
	//TODO add check for tolerance 0 <= tolerance <= 100
}

func main() {
	flagConfig()

	if p.FlowPath != "" {
		p.OfflineMode()
		FlowStats()
		p.WriteObjToJSONFile(time.Now().Format(time.RFC3339)+"_report.json", p.PeriodiFlows)
		return
	}

	p.LiveMode()
	FlowStats()
	p.WriteObjToJSONFile(time.Now().Format(time.RFC3339)+"_report.json", p.PeriodiFlows)
}

func FlowStats() {
	json, err := p.PeriodiFlows.Marshal()
	if err != nil {
		return
	}
	fmt.Printf("%s", string(json))
}
