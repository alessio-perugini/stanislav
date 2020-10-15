package stanislav

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
)

type proto interface {
	run()
	shutdown()
}

var PossibleThreat = make(map[string][]string)

func LiveMode() {
	var wg sync.WaitGroup
	var signalCh = make(chan os.Signal, 1)

	opts = GetOptions()
	runtime.GOMAXPROCS(opts.getCPU())
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)
	logger = opts.Logger

	//BlacklistModule
	LoadBlockListedC2()

	netflow9 := NewNetflowV9()
	peng := New(Conf)
	protos := []proto{netflow9, peng}

	for _, p := range protos {
		wg.Add(1)
		go func(p proto) {
			defer wg.Done()
			p.run()
		}(p)
	}

	<-signalCh

	for _, p := range protos {
		wg.Add(1)
		go func(p proto) {
			defer wg.Done()
			p.shutdown()
		}(p)
	}

	wg.Wait()

	//gathering all possible new periodicity, because we don't update on every entry

	for k, v := range PeriodiFlows {
		if val, ok := PossibleThreat[k]; ok {
			last := len(val) - 1
			lastPeriodic := fmt.Sprintf("periodic frequency: %.2fs seen %d times.", v.TWDuration, v.PeriodicityCounter)
			if val[last] != lastPeriodic {
				PossibleThreat[k][last] = lastPeriodic
			}
		}
	}

}
