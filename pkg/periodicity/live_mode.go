package periodicity

import (
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

func LiveMode() {
	var (
		wg       sync.WaitGroup
		signalCh = make(chan os.Signal, 1)
	)
	opts = GetOptions()
	runtime.GOMAXPROCS(opts.getCPU())
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)
	logger = opts.Logger

	netflow9 := NewNetflowV9()
	protos := []proto{netflow9}

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
}
