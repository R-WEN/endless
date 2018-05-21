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

type TLSConfig struct {
	Certificate              string   // file name of Cert Key
	Key                      string   // file name of Cert Key
	ProtocolMinVersion       uint16   // ?? - defaults? I think to 1.2 the highest level - so why set
	ProtocolMaxVersion       uint16   // ?? - defaults?
	Ciphers                  []uint16 // Flags of Ciphers - need special processing to read in
	PreferServerCipherSuites bool     // Flags of Ciphers - need special processing to read in
}

type endlessListener struct {
	net.Listener
	stopped bool
	server  *endlessServer
}

type endlessConn struct {
	net.Conn
	server *endlessServer
}
