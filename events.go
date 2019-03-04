package sshh

import (
	"log"
	"net"

	"golang.org/x/crypto/ssh"
)

// Event represents an event on the server.
type Event interface {
}

// EventHandler allows for handling of server event notification. Must be non-blocking.
type EventHandler func(Event)

// ServerStartedEvent is emitted when the server.Start() is called but
// before the net.Listener is created. If there is an error creating the
// net.Listener, an error is returned from the ListenAndServe method.
type ServerStartedEvent struct{}

// ServerStoppedEvent is emitted when the server stops but before all the connections have been closed.
type ServerStoppedEvent struct{}

// ConnectionOpenedEvent is emitted when a connection is successfully established.
type ConnectionOpenedEvent struct {
	LocalAddr  net.Addr
	RemoteAddr net.Addr
}

// ConnectionClosedEvent is emitted when the connection is closed.
type ConnectionClosedEvent struct {
	LocalAddr  net.Addr
	RemoteAddr net.Addr
}

// MaxConnectionsEvent is emitted when the maximum connection limit is reached.
type MaxConnectionsEvent struct {
}

// MaxClientConnectionsEvent is emitted when a client reaches the maximum client connection limit.
type MaxClientConnectionsEvent struct {
	LocalAddr  net.Addr
	RemoteAddr net.Addr
}

// ConnectionFailedEvent is emitted when theres a connection failure.
type ConnectionFailedEvent struct {
	Error error
}

// ListenerOpenedEvent is emitted when the listener is opened.
type ListenerOpenedEvent struct {
	Addr *net.TCPAddr
}

// ListenerClosedEvent is emitted when the listener is closed.
type ListenerClosedEvent struct {
}

// HandshakeFailedEvent is emitted when the SSH handshake failed.
type HandshakeFailedEvent struct {
	LocalAddr  net.Addr
	RemoteAddr net.Addr
	Error      error
}

// HandshakeSuccessfulEvent is emitted when the SSH handshake was successful.
type HandshakeSuccessfulEvent struct {
	LocalAddr  net.Addr
	RemoteAddr net.Addr
}

// RequestEvent is emitted when a gloabl request is recieved on a connection.
type RequestEvent struct {
	Conn        *ssh.ServerConn
	RequestType string
}

// UnknownRequestEvent is emitted when the global request does not have a handler.
type UnknownRequestEvent struct {
	Conn        *ssh.ServerConn
	RequestType string
}

// ChannelEvent is emitted when a channel is recieved on a connection.
type ChannelEvent struct {
	Conn        *ssh.ServerConn
	ChannelType string
}

// UnknownChannelEvent is emitted when the channel type does not have a handler.
type UnknownChannelEvent struct {
	Conn        *ssh.ServerConn
	ChannelType string
}

// LoggingEventHandler logs all the events to the standard logging interface.
func LoggingEventHandler(logger *log.Logger) EventHandler {
	return func(evt Event) {
		switch e := evt.(type) {
		case *ServerStartedEvent:
			logger.Println("Server started")
		case *ServerStoppedEvent:
			logger.Println("Server stopped")
		case *ConnectionOpenedEvent:
			logger.Printf("Connection opened local=%s remote=%s\n", e.LocalAddr, e.RemoteAddr)
		case *ConnectionClosedEvent:
			logger.Printf("Connection closed local=%s remote=%s\n", e.LocalAddr, e.RemoteAddr)
		case *MaxConnectionsEvent:
			logger.Println("Connection limit reached")
		case *MaxClientConnectionsEvent:
			logger.Printf("Client connection limit reached local=%s remote=%s\n", e.LocalAddr, e.RemoteAddr)
		case *ConnectionFailedEvent:
			logger.Printf("Connection failed err=%s\n", e.Error)
		case *ListenerOpenedEvent:
			logger.Printf("Listener opened addr=%s\n", e.Addr)
		case *ListenerClosedEvent:
			logger.Println("Listener closed")
		case *HandshakeFailedEvent:
			logger.Printf("Handshake failed local=%s remote=%s err=%s\n", e.LocalAddr, e.RemoteAddr, e.Error)
		case *HandshakeSuccessfulEvent:
			logger.Printf("Handshake successful local=%s remote=%s\n", e.LocalAddr, e.RemoteAddr)
		case *RequestEvent:
			if e.Conn == nil {
				logger.Printf("Global request type=%s conn=nil\n", e.RequestType)
				return
			}
			logger.Printf("Global request type=%s user=%s local=%s remote=%s\n", e.RequestType, e.Conn.User(), e.Conn.LocalAddr(), e.Conn.RemoteAddr())
		case *UnknownRequestEvent:
			if e.Conn == nil {
				logger.Printf("Unknown global request type=%s conn=nil\n", e.RequestType)
				return
			}
			logger.Printf("Unknown global request type=%s user=%s local=%s remote=%s\n", e.RequestType, e.Conn.User(), e.Conn.LocalAddr(), e.Conn.RemoteAddr())
		case *ChannelEvent:

			if e.Conn == nil {
				logger.Printf("Channel created type=%s conn=nil\n", e.ChannelType)
				return
			}
			logger.Printf("Channel created type=%s user=%s local=%s remote=%s\n", e.ChannelType, e.Conn.User(), e.Conn.LocalAddr(), e.Conn.RemoteAddr())
		case *UnknownChannelEvent:

			if e.Conn == nil {
				logger.Printf("Unknown global request type=%s conn=nil\n", e.ChannelType)
				return
			}
			logger.Printf("Unknown global request type=%s user=%s local=%s remote=%s\n", e.ChannelType, e.Conn.User(), e.Conn.LocalAddr(), e.Conn.RemoteAddr())
		default:
		}
	}
}
