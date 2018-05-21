package endless

import (
	"net"
	"net/http"
	"os"
	"sync"
)

const (
	PRE_SIGNAL = iota
	POST_SIGNAL

	STATE_INIT
	STATE_RUNNING
	STATE_SHUTTING_DOWN
	STATE_TERMINATE
)

type endlessServer struct {
	http.Server
	EndlessListener  net.Listener
	SignalHooks      map[int]map[os.Signal][]func()
	tlsInnerListener *endlessListener
	wg               sync.WaitGroup
	sigChan          chan os.Signal
	isChild          bool
	state            uint8
	lock             *sync.RWMutex
	BeforeBegin      func(add string)
}
