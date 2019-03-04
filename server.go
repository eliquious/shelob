package sshh

import (
	"fmt"
	"net"
	"os/signal"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/context"
)

// New creates a new server with the given config. If the Bind address is invalid an
// error will be returned when started. If there is an error starting the TCP server,
// the error will be returned.
func New(ctx context.Context, conf *Config) (*Server, error) {

	// Set default max deadline of 1 second
	if conf.MaxDeadline == 0 {
		conf.MaxDeadline = time.Second
	}

	// ServerConfig is required.
	if conf.ServerConfig == nil {
		return nil, fmt.Errorf("ssh.ServerConfig must be provided")
	}

	// Wrap provided public key callback to inject permission extensions
	// for getting the public key information in the session.
	if conf.ServerConfig.PublicKeyCallback != nil {
		conf.ServerConfig.PublicKeyCallback = pubKeyCallbackWrapper(conf.ServerConfig.PublicKeyCallback)
	}

	// Add private key to ServerConfig
	if conf.PrivateKey != nil {
		conf.ServerConfig.AddHostKey(conf.PrivateKey)
	}

	ctx, cancel := context.WithCancel(ctx)
	closeCh := make(chan *net.TCPConn, 1)
	doneCh := make(chan struct{})
	return &Server{ctx, cancel, closeCh, doneCh, conf, conf.ServerConfig, nil, nil}, nil
}

// PublicKeyCallback represents the function type for Public Key auth in crypto/ssh.
type PublicKeyCallback func(meta ssh.ConnMetadata, key ssh.PublicKey) (perm *ssh.Permissions, err error)

const permKeyType = "pub-key-type"
const permKeyData = "pub-key-data"
const permKeyFingerprint = "pub-key-fingerprint"

// Inject the public key info into the permission extensions
func pubKeyCallbackWrapper(cb PublicKeyCallback) PublicKeyCallback {
	return func(meta ssh.ConnMetadata, key ssh.PublicKey) (perm *ssh.Permissions, err error) {
		if cb == nil {
			return nil, ssh.ErrNoAuth
		}

		perm, err = cb(meta, key)
		if err != nil {
			return nil, err
		}

		// Ensure perm.Extensions exists
		if perm == nil {
			perm = &ssh.Permissions{
				Extensions: map[string]string{},
			}
		} else if perm != nil && perm.Extensions == nil {
			perm.Extensions = map[string]string{}
		}

		// Add builtin extensions
		perm.Extensions[permKeyType] = key.Type()
		perm.Extensions[permKeyData] = string(key.Marshal())
		perm.Extensions[permKeyFingerprint] = ssh.FingerprintLegacyMD5(key)
		return perm, nil
	}
}

// Server handles all the incoming connections as well as handler dispatch.
type Server struct {
	ctx       context.Context
	cancel    context.CancelFunc
	closeCh   chan *net.TCPConn
	doneCh    chan struct{}
	config    *Config
	sshConfig *ssh.ServerConfig

	Addr     *net.TCPAddr
	listener *net.TCPListener
}

// ListenAndServe starts accepting client connections.
func (s *Server) ListenAndServe() error {
	s.handleEvent(&ServerStartedEvent{})

	// Validate the ssh bind addr
	if s.config.Addr == "" {
		s.config.Addr = ":22"
	}

	// Open SSH socket listener
	sshAddr, e := net.ResolveTCPAddr("tcp", s.config.Addr)
	if e != nil {
		return fmt.Errorf("ssh server: Invalid tcp address")
	}

	// Create listener
	listener, err := net.ListenTCP("tcp", sshAddr)
	if err != nil {
		return err
	}
	s.Addr = listener.Addr().(*net.TCPAddr)
	s.listener = listener
	s.handleEvent(&ListenerOpenedEvent{s.Addr})

	s.listen()
	return nil
}

// Stop stops the server and kills all goroutines. This method is blocking.
func (s *Server) Stop() {
	s.cancel()
	<-s.doneCh
}

func (s *Server) handleEvent(evt Event) {
	if s.config.EventHandler != nil {
		s.config.EventHandler(evt)
	}
}

// listen accepts new connections and handles the conversion from TCP to SSH connections.
func (s *Server) listen() {
	defer close(s.doneCh)

	var wg sync.WaitGroup
	var openConnections int
	clientConnections := make(map[string]int)

	initialDeadline := 5 * time.Millisecond
	deadline := initialDeadline
OUTER:
	for {
		if deadline > s.config.MaxDeadline {
			deadline = s.config.MaxDeadline
		}

		// Accepts will only block for deadline
		s.listener.SetDeadline(time.Now().Add(deadline))

		select {

		// Stop server on channel receive
		case <-s.ctx.Done():
			s.handleEvent(&ServerStoppedEvent{})
			s.listener.Close()
			s.handleEvent(&ListenerClosedEvent{})
			break OUTER
		case <-s.config.SignalChan:
			s.cancel()

			// Stop listening for signals and close channel
			signal.Stop(s.config.SignalChan)
			// close(s.config.SignalChan)
			continue
		case tcpConn := <-s.closeCh:
			wg.Done()
			deadline = initialDeadline

			openConnections--
			tcpAddr := tcpConn.RemoteAddr().(*net.TCPAddr)
			if _, ok := clientConnections[tcpAddr.IP.String()]; ok {
				clientConnections[tcpAddr.IP.String()]--
			}

			s.handleEvent(&ConnectionClosedEvent{
				LocalAddr:  tcpConn.LocalAddr(),
				RemoteAddr: tcpConn.RemoteAddr(),
			})
			continue
		default:

			// Accept new connection
			conn, err := s.listener.Accept()
			if err != nil {

				// Connection timeout
				if neterr, ok := err.(net.Error); ok && neterr.Timeout() {

					// Increase timeout deadline
					deadline *= 2

				} else {

					// Connection failed
					s.handleEvent(&ConnectionFailedEvent{Error: err})
				}
				continue
			}
			// Successful connection. There may be more..
			deadline = initialDeadline

			// Get TCP connection
			tcpConn := conn.(*net.TCPConn)
			tcpAddr := tcpConn.RemoteAddr().(*net.TCPAddr)
			ip := tcpAddr.IP.String()

			// Check connection limit
			if s.config.MaxConnections > 0 && openConnections >= s.config.MaxConnections {

				// Too many connections; Close connection
				tcpConn.Close()
				s.handleEvent(&ConnectionClosedEvent{
					LocalAddr:  tcpConn.LocalAddr(),
					RemoteAddr: tcpConn.RemoteAddr(),
				})
				continue
			}

			// Check max connections per IP
			if s.config.MaxClientConnections > 0 {
				if val, ok := clientConnections[ip]; ok && val >= s.config.MaxClientConnections {

					// Too many connections per IP; Close connection
					tcpConn.Close()
					s.handleEvent(&ConnectionClosedEvent{
						LocalAddr:  tcpConn.LocalAddr(),
						RemoteAddr: tcpConn.RemoteAddr(),
					})
					continue
				}
			}

			// Increment connection counters
			wg.Add(1)
			openConnections++
			clientConnections[ip]++

			// Max connections has been reached
			if openConnections == s.config.MaxConnections {
				s.handleEvent(&MaxConnectionsEvent{})
			}

			// Max client connections has been reached.
			if clientConnections[ip] == s.config.MaxClientConnections {
				s.handleEvent(&MaxClientConnectionsEvent{
					LocalAddr:  tcpConn.LocalAddr(),
					RemoteAddr: tcpConn.RemoteAddr(),
				})
			}

			// Connection will automatically expire after the deadline
			if s.config.MaxConnectionDuration > 0 {
				tcpConn.SetDeadline(time.Now().Add(s.config.MaxConnectionDuration))
			}

			// Handle connection
			s.handleEvent(&ConnectionOpenedEvent{
				LocalAddr:  tcpConn.LocalAddr(),
				RemoteAddr: tcpConn.RemoteAddr(),
			})
			go s.handleTCPConn(tcpConn)
		}
	}

	// Wait for all connections to close
	wg.Wait()
}

func (s *Server) closeConn(tcpConn *net.TCPConn) {
	tcpConn.Close()
	s.closeCh <- tcpConn
}

func (s *Server) handleTCPConn(tcpConn *net.TCPConn) {
	defer s.closeConn(tcpConn)

	// Allows for connection modification. Need to go back to net.Conn interface for easier wrapping.
	var conn net.Conn = tcpConn
	if s.config.ConnectionCallback != nil {
		conn = s.config.ConnectionCallback(tcpConn)
	}

	// Convert to SSH connection
	sshConn, channels, requests, err := ssh.NewServerConn(conn, s.sshConfig)
	if err != nil {
		s.handleEvent(&HandshakeFailedEvent{
			Error:      err,
			LocalAddr:  tcpConn.LocalAddr(),
			RemoteAddr: tcpConn.RemoteAddr(),
		})
		return
	}
	s.handleEvent(&HandshakeSuccessfulEvent{
		LocalAddr:  tcpConn.LocalAddr(),
		RemoteAddr: tcpConn.RemoteAddr(),
	})

	// Close connection on exit
	defer sshConn.Close()
	defer sshConn.Wait()

	// Handle global requests
	ctx, cancel := context.WithCancel(WithServerConn(s.ctx, sshConn))
	defer cancel()
	go s.handleRequests(ctx, requests)

	// Handle connection channels
	for ch := range channels {

		handler, found := s.config.ChannelHandlers[ch.ChannelType()]
		if !found {
			ch.Reject(ssh.UnknownChannelType, "unsupported channel type")

			s.handleEvent(&UnknownChannelEvent{
				Conn:        sshConn,
				ChannelType: ch.ChannelType(),
			})
		} else {
			s.handleEvent(&ChannelEvent{
				Conn:        sshConn,
				ChannelType: ch.ChannelType(),
			})
			go handler.HandleChannel(ctx, ch)
		}
	}
}

func (s *Server) handleRequests(ctx context.Context, in <-chan *ssh.Request) {
	conn, _ := SSHServerConn(ctx)
	for req := range in {
		handler, found := s.config.RequestHandlers[req.Type]
		if !found {
			s.handleEvent(&UnknownRequestEvent{
				RequestType: req.Type,
				Conn:        conn,
			})

			if req.WantReply {
				req.Reply(false, nil)
			}
			continue
		}

		s.handleEvent(&RequestEvent{
			RequestType: req.Type,
			Conn:        conn,
		})

		ret, payload := handler.HandleRequest(ctx, req)
		if req.WantReply {
			req.Reply(ret, payload)
		}
	}
}
