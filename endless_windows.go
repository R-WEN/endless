// code dedicated to windows

// +build windows

package endless

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"
	// "github.com/fvbock/uds-go/introspect"
)

var (
	DefaultReadTimeOut    time.Duration
	DefaultWriteTimeOut   time.Duration
	DefaultMaxHeaderBytes int
	DefaultHammerTime     time.Duration
)

func init() {

	DefaultMaxHeaderBytes = 0 // use http.DefaultMaxHeaderBytes - which currently is 1 << 20 (1MB)

	DefaultHammerTime = 60 * time.Second

}

/*
NewServer returns an intialized endlessServer Object. Calling Serve on it will
actually "start" the server.
*/
func NewServer(addr string, handler http.Handler) (srv *endlessServer) {

	srv = &endlessServer{}

	srv.Server.Addr = addr
	srv.Server.ReadTimeout = DefaultReadTimeOut
	srv.Server.WriteTimeout = DefaultWriteTimeOut
	srv.Server.MaxHeaderBytes = DefaultMaxHeaderBytes
	srv.Server.Handler = handler

	srv.BeforeBegin = func(addr string) {
		log.Println(os.Getpid(), addr)
	}

	return
}

/*
ListenAndServe listens on the TCP network address addr and then calls Serve
with handler to handle requests on incoming connections. Handler is typically
nil, in which case the DefaultServeMux is used.
*/
func ListenAndServe(addr string, handler http.Handler) error {
	server := NewServer(addr, handler)
	return server.ListenAndServe()
}

/*
ListenAndServeTLS acts identically to ListenAndServe, except that it expects
HTTPS connections. Additionally, files containing a certificate and matching
private key for the server must be provided. If the certificate is signed by a
certificate authority, the certFile should be the concatenation of the server's
certificate followed by the CA's certificate.
*/
func ListenAndServeTLS(addr string, certFile string, keyFile string, handler http.Handler) error {
	server := NewServer(addr, handler)
	return server.ListenAndServeTLS(certFile, keyFile)
}

// PJS
// func (srv *endlessServer) ListenAndServeTLSWithSNI(tlsConfigs []TLSConfig) (err error) {
// func ListenAndServeTLSWithSNI(srv *http.Server, tlsConfigs []TLSConfig) (err error) {
func ListenAndServeTLSWithSNI(addr string, handler http.Handler, tlsConfigs []TLSConfig) (err error) {
	server := NewServer(addr, handler)
	return server.ListenAndServeTLSWithSNI(tlsConfigs)
}

/*
Serve accepts incoming HTTP connections on the listener l, creating a new
service goroutine for each. The service goroutines read requests and then call
handler to reply to them. Handler is typically nil, in which case the
DefaultServeMux is used.

In addition to the stl Serve behaviour each connection is added to a
sync.Waitgroup so that all outstanding connections can be served before shutting
down the server.
*/
func (srv *endlessServer) Serve() (err error) {
	err = srv.Server.Serve(srv.EndlessListener)
	return
}

/*
ListenAndServe listens on the TCP network address srv.Addr and then calls Serve
to handle requests on incoming connections. If srv.Addr is blank, ":http" is
used.
*/
func (srv *endlessServer) ListenAndServe() (err error) {
	addr := srv.Addr
	if addr == "" {
		addr = ":http"
	}

	l, err := srv.getListener(addr)
	if err != nil {
		log.Println(err)
		return
	}

	srv.EndlessListener = newEndlessListener(l, srv)

	srv.BeforeBegin(srv.Addr)

	return srv.Serve()
}

/*
ListenAndServeTLS listens on the TCP network address srv.Addr and then calls
Serve to handle requests on incoming TLS connections.

Filenames containing a certificate and matching private key for the server must
be provided. If the certificate is signed by a certificate authority, the
certFile should be the concatenation of the server's certificate followed by the
CA's certificate.

If srv.Addr is blank, ":https" is used.
*/
func (srv *endlessServer) ListenAndServeTLS(certFile, keyFile string) (err error) {
	addr := srv.Addr
	if addr == "" {
		addr = ":https"
	}

	config := &tls.Config{}
	if srv.TLSConfig != nil {
		*config = *srv.TLSConfig
	}
	if config.NextProtos == nil {
		config.NextProtos = []string{"http/1.1"}
	}

	config.NextProtos = append(config.NextProtos, "h2") // Enable HTTP2.0 progocall

	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return
	}

	l, err := srv.getListener(addr)
	if err != nil {
		log.Println(err)
		return
	}

	srv.tlsInnerListener = newEndlessListener(l, srv)
	srv.EndlessListener = tls.NewListener(srv.tlsInnerListener, config)

	return srv.Serve()
}

// PJS mod 1
// func ListenAndServeTLSWithSNI(srv *http.Server, tlsConfigs []TLSConfig) (err error) {
func (srv *endlessServer) ListenAndServeTLSWithSNI(tlsConfigs []TLSConfig) (err error) {
	addr := srv.Addr
	if addr == "" {
		addr = ":https"
	}

	//config := &tls.Config{}
	//if srv.TLSConfig != nil {
	//	*config = *srv.TLSConfig
	//}
	//if config.NextProtos == nil {
	//	config.NextProtos = []string{"http/1.1"}
	//}

	var config *tls.Config
	if srv.TLSConfig != nil {
		config = srv.TLSConfig
	} else {
		config = new(tls.Config)
	}

	// return strSliceContains(srv.TLSConfig.NextProtos, http2NextProtoTLS)
	config.NextProtos = append(config.NextProtos, "h2") // Enable HTTP2.0 progocall

	config.MinVersion = tls.VersionTLS11
	config.CipherSuites = tlsConfigs[0].Ciphers

	//config.Certificates = make([]tls.Certificate, 1)
	//config.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
	//if err != nil {
	//	return
	//}
	// PJS - Load set of certificate paris instead of single certificate.
	config.Certificates = make([]tls.Certificate, len(tlsConfigs))
	for i, tlsConfig := range tlsConfigs {
		// PJS params are file names, can be relative
		config.Certificates[i], err = tls.LoadX509KeyPair(tlsConfig.Certificate, tlsConfig.Key) // PJS - reads and parses certs
		if err != nil {
			return
		}
	}
	config.BuildNameToCertificate()

	l, err := srv.getListener(addr)
	if err != nil {
		log.Println(err)
		return
	}

	srv.tlsInnerListener = newEndlessListener(l, srv)
	srv.EndlessListener = tls.NewListener(srv.tlsInnerListener, config)

	return srv.Serve()
}

/*
getListener either opens a new socket to listen on, or takes the acceptor socket
it got passed when restarted.
*/
func (srv *endlessServer) getListener(laddr string) (l net.Listener, err error) {
	l, err = net.Listen("tcp", laddr)
	if err != nil {
		err = fmt.Errorf("net.Listen error: %v", err)
		return
	}
	return
}

func (el *endlessListener) Accept() (c net.Conn, err error) {
	tc, err := el.Listener.(*net.TCPListener).AcceptTCP()
	if err != nil {
		return
	}

	tc.SetKeepAlive(true)                  // see http.tcpKeepAliveListener
	tc.SetKeepAlivePeriod(3 * time.Minute) // see http.tcpKeepAliveListener

	c = endlessConn{
		Conn:   tc,
		server: el.server,
	}

	el.server.wg.Add(1)
	return
}

func newEndlessListener(l net.Listener, srv *endlessServer) (el *endlessListener) {
	el = &endlessListener{
		Listener: l,
		server:   srv,
	}

	return
}

func (el *endlessListener) Close() error {

	el.stopped = true
	return el.Listener.Close()
}

func (el *endlessListener) File() *os.File {
	// returns a dup(2) - FD_CLOEXEC flag *not* set
	tl := el.Listener.(*net.TCPListener)
	fl, _ := tl.File()
	return fl
}

func (w endlessConn) Close() error {
	err := w.Conn.Close()
	if err == nil {
		w.server.wg.Done()
	}
	return err
}

/*
RegisterSignalHook registers a function to be run PRE_SIGNAL or POST_SIGNAL for
a given signal. PRE or POST in this case means before or after the signal
related code endless itself runs
*/
func (srv *endlessServer) RegisterSignalHook(prePost int, sig os.Signal, f func()) (err error) {
	return
}
