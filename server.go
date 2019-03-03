package sshh

import (
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/context"
)

// New creates a new server with the given config. The server will call `cfg.SSHConfig()` to setup
// the server. If an error occurs it will be returned. If the Bind address is empty or invalid
// an error will be returned. If there is an error starting the TCP server, the error will be returned.
func New(ctx context.Context, conf *Config) (*Server, error) {

	// Set default max deadline of 1 second
	if conf.MaxDeadline == 0 {
		conf.MaxDeadline = time.Second
	}

	// Setup the SSH server config
	sshConfig := &ssh.ServerConfig{
		NoClientAuth:      false,
		PasswordCallback:  conf.PasswordCallback,
		PublicKeyCallback: conf.PublicKeyCallback,
		AuthLogCallback:   conf.AuthLogCallback,
	}
	sshConfig.AddHostKey(conf.PrivateKey)

	ctx, cancel := context.WithCancel(ctx)
	closeCh := make(chan *net.TCPConn, 1)
	doneCh := make(chan struct{})
	return &Server{ctx, cancel, closeCh, doneCh, conf, sshConfig, nil, nil}, nil
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

	// Shutting down SSH server
	s.handleEvent(&ServerStoppedEvent{})
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
			s.listener.Close()
			s.handleEvent(&ListenerClosedEvent{})
			break OUTER
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
					s.handleEvent(&ConnectionFailedEvent{})
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

	// Convert to SSH connection
	sshConn, channels, requests, err := ssh.NewServerConn(tcpConn, s.sshConfig)
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
	ctx := WithServerConn(s.ctx, sshConn)
	go s.handleRequests(ctx, requests)

	// Handle connection channels
	for ch := range channels {
		handler, found := s.config.ChannelHandlers[ch.ChannelType()]
		if !found {
			ch.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}
		go handler.HandleChannel(ctx, ch)
	}
}

func (s *Server) handleRequests(ctx context.Context, in <-chan *ssh.Request) {
	for req := range in {
		handler, found := s.config.RequestHandlers[req.Type]
		if !found && req.WantReply {
			req.Reply(false, nil)
			continue
		}

		ret, payload := handler.HandleRequest(ctx, req)
		if req.WantReply {
			req.Reply(ret, payload)
		}
	}
}
