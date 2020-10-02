package stanislav

import (
	"log"
	"testing"
)

func TestIsBroadcastAddress(t *testing.T) {
	r := IsBroadcastAddress("192.168.1.1")
	if r {
		log.Fatal("should be false")
	}
	r = IsBroadcastAddress("192.168.1.255")
	if !r {
		log.Fatal("should be true")
	}
}
