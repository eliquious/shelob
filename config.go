package sshh

import (
	"net"
	"time"

	// log "github.com/mgutz/logxi/v1"

	"golang.org/x/crypto/ssh"
)

// Config is used to setup the Server, including the server config and the Handlers.
type Config struct {

	// Addr specifies the bind address the SSH server will listen on.
	Addr string

	// MaxConnections is the maximum connections allowed by the server.
	MaxConnections int

	// MaxClientConnections is the maximum connections from 1 IP address.
	MaxClientConnections int

	// MaxDeadline is the maximum time the listener will block
	// between connections. As a consequence, this duration
	// also sets the max length of time the SSH server will
	// be unresponsive before shutting down.
	MaxDeadline time.Duration

	// MaxConnectionDuration is the maximum length of time a connection can stay open.
	MaxConnectionDuration time.Duration

	// RequestHandlers is a map of RequestHandlers which handle certain global ssh.Requests.
	RequestHandlers map[string]RequestHandler

	// ChannelHandlers is a map of ChannelHandlers which handle SSH channels based on type.
	ChannelHandlers map[string]ChannelHandler

	// ConnectionCallback allows for modification of the incoming network connection and/or connection wrapping
	ConnectionCallback func(net.Conn) net.Conn

	// EventHandler handles events for logging, etc. Must be non-blocking.
	EventHandler EventHandler

	// PrivateKey is added to the SSH config as a host key.
	PrivateKey ssh.Signer

	// ServerConfig configures the underlying SSH server. It allows for full control of the authenication mechanisms.
	ServerConfig *ssh.ServerConfig
}
