package sshh

import (
	"net"
)

// Event represents an event on the server.
type Event interface {
}

// EventHandler allows for handling of server event notification. Must be non-blocking.
type EventHandler func(Event)

// ServerStartedEvent is fired when the server.Start() is called but
// before the net.Listener is created. If there is an error creating the
// net.Listener, an error is returned from the ListenAndServe method.
type ServerStartedEvent struct{}

// ServerStoppedEvent is fired when the server stops but before all the connections have been closed.
type ServerStoppedEvent struct{}

// ConnectionOpenedEvent is fired when a connection is successfully established.
type ConnectionOpenedEvent struct {
	LocalAddr  net.Addr
	RemoteAddr net.Addr
}

// ConnectionClosedEvent is fired when the connection is closed.
type ConnectionClosedEvent struct {
	LocalAddr  net.Addr
	RemoteAddr net.Addr
}

// MaxConnectionsEvent is fired when the maximum connection limit is reached.
type MaxConnectionsEvent struct {
}

// MaxClientConnectionsEvent is fired when a client reaches the maximum client connection limit.
type MaxClientConnectionsEvent struct {
	LocalAddr  net.Addr
	RemoteAddr net.Addr
}

// ConnectionFailedEvent is fired when theres a connection failure.
type ConnectionFailedEvent struct{}

// ListenerOpenedEvent is fired when the listener is opened.
type ListenerOpenedEvent struct {
	Addr *net.TCPAddr
}

// ListenerClosedEvent is fired when the listener is closed.
type ListenerClosedEvent struct {
}

// HandshakeFailedEvent is fired when the SSH handshake failed.
type HandshakeFailedEvent struct {
	LocalAddr  net.Addr
	RemoteAddr net.Addr
	Error      error
}

// HandshakeSuccessfulEvent is fired when the SSH handshake was successful.
type HandshakeSuccessfulEvent struct {
	LocalAddr  net.Addr
	RemoteAddr net.Addr
}
