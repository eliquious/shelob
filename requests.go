package sshh

import (
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/context"
)

type contextKey string

const keySSHConn contextKey = "server-conn"
const keyEventHandler contextKey = "event-handler"

// WithServerConn adds a ssh.ServerConn to a context.
func WithServerConn(ctx context.Context, sshConn *ssh.ServerConn) context.Context {
	return context.WithValue(ctx, keySSHConn, sshConn)
}

//SSHServerConn returns a ssh.ServerConn from a context
func SSHServerConn(ctx context.Context) (*ssh.ServerConn, bool) {
	srv, ok := ctx.Value(keySSHConn).(*ssh.ServerConn)
	return srv, ok
}

// RequestHandler handles global requests on a connection.
type RequestHandler interface {
	HandleRequest(ctx context.Context, req *ssh.Request) (ok bool, payload []byte)
}

// ChannelHandler handles channels inside a connection.
type ChannelHandler interface {
	HandleChannel(ctx context.Context, ch ssh.NewChannel)
}
