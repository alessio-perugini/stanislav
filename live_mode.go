package stanislav

import (
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"
)

type proto interface {
	run()
	shutdown()
}

var (
	config = Config{
		NumberOfBin:        128,
		SizeBitmap:         1024,
		InfluxUrl:          "http://localhost",
		InfluxPort:         9999,
		InfluxBucket:       "",
		InfluxOrganization: "",
		InfluxAuthToken:    "",
		SaveFilePath:       "peng_result.csv",
		UseInflux:          false,
		Verbose:            uint(1),
		NetworkInterface:   "eno1",
		Ja3BlackListFile:   "/media/ale/DatiD/Progetti/Progetti2019/GoPrj/stanislav/resources/ja3/ja3_fingerprints.csv",
		GeoIpDb:            "/media/ale/DatiD/Progetti/Progetti2019/GoPrj/stanislav/resources/GeoLite2-City.mmdb",
		TimeFrame:          time.Second * 15,
	}

	showInterfaceNames bool
	versionFlag        bool
	commit             = "commithash"
)

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
	peng := New(&config)
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
}
