package shelob

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"sync/atomic"

	"github.com/google/shlex"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/context"
)

// Session represents a user's SSH session.
type Session interface {
	ssh.Channel

	// User returns the username used when establishing the SSH connection.
	User() string

	// RemoteAddr returns the net.Addr of the client side of the connection.
	RemoteAddr() net.Addr

	// LocalAddr returns the net.Addr of the server side of the connection.
	LocalAddr() net.Addr

	// Environ returns a copy of strings representing the environment set by the
	// user for this session, in the form "key=value".
	Environ() []string

	// Exit sends an exit status and then closes the session.
	Exit(code int) error

	// Command returns a shell parsed slice of arguments that were provided by the
	// user. Shell parsing splits the command string according to POSIX shell rules,
	// which considers quoting not just whitespace.
	Command() []string

	// PublicKey returns the PublicKey used to authenticate. If a public key was not
	// used it will return nil.
	PublicKey() ssh.PublicKey

	// Permissions returns a copy of the Permissions object that was available for
	// setup in the auth handlers.
	Permissions() *ssh.Permissions

	// Pty returns PTY information, a channel of window size changes, and a boolean
	// of whether or not a PTY was accepted for this session.
	Pty() (Pty, <-chan Window, bool)

	WriteString(s string) (n int, err error)

	// Signals registers a channel to receive signals sent from the client. The
	// channel must handle signal sends or it will block the SSH request loop.
	// Registering nil will unregister the channel from signal sends. During the
	// time no channel is registered signals are buffered up to a reasonable amount.
	// If there are buffered signals when a channel is registered, they will be
	// sent in order on the channel immediately after registering.
	Signals(c chan<- os.Signal)
}

// SessionHandler handles session channels.
type SessionHandler func(ctx context.Context, s Session) int

// NewSessionChannelHandler creates a new ChannelHandler for session channels.
func NewSessionChannelHandler(handler SessionHandler, allowPty bool, allowAgentFwd bool) ChannelHandler {
	return &sessionChannelHandler{handler, allowPty, allowAgentFwd}
}

type sessionChannelHandler struct {
	handler       SessionHandler
	allowPty      bool
	allowAgentFwd bool
}

func (s *sessionChannelHandler) HandleChannel(ctx context.Context, newch ssh.NewChannel) {

	// ssh.ServerConn should be in the context.
	conn, ok := SSHServerConn(ctx)
	if !ok {
		newch.Reject(ssh.ConnectionFailed, "server error")
		return
	}
	defer conn.Close()

	ch, reqs, err := newch.Accept()
	if err != nil {
		newch.Reject(ssh.ConnectionFailed, "failed to accept channel")
		return
	}
	defer ch.Close()

	s.handleRequests(ctx, conn, ch, reqs)
}

func (s *sessionChannelHandler) handleRequests(ctx context.Context, conn *ssh.ServerConn, ch ssh.Channel, reqs <-chan *ssh.Request) {

	// Signal handling
	var signalCh chan<- os.Signal
	signalChCh := make(chan chan<- os.Signal)
	signalBuffer := []os.Signal{}

	// Create session
	sess := &session{
		Channel:    ch,
		conn:       conn,
		signalChCh: signalChCh,
		handler:    s.handler,
	}
	for {
		select {
		case <-ctx.Done():
			return
		case sigCh := <-signalChCh:
			signalCh = sigCh

			// Send buffered signals if any
			if len(signalBuffer) > 0 {
				go func(ch chan<- os.Signal, buf []os.Signal) {
					for _, sig := range buf {
						ch <- sig
					}
				}(signalCh, signalBuffer)
			}
		case req := <-reqs:
			if req == nil {
				continue
			}

			switch req.Type {
			case "shell", "exec":
				sess.handle(ctx, req)

			case "env":
				if sess.hasBeenHandled() {
					req.Reply(false, nil)
					continue
				}

				// Parse payload
				var kv struct{ Key, Value string }
				ssh.Unmarshal(req.Payload, &kv)
				sess.env = append(sess.env, fmt.Sprintf("%s=%s", kv.Key, kv.Value))
				req.Reply(true, nil)
			case "signal":

				var payload struct{ Signal string }
				ssh.Unmarshal(req.Payload, &payload)

				sig, err := toSignal(payload.Signal)
				if err != nil {

					// Unknown signal
					continue
				}

				if signalCh != nil {
					signalCh <- sig
				} else {
					if len(signalBuffer) < 128 {
						signalBuffer = append(signalBuffer, sig)
					}
				}

			case "pty-req":
				if !s.allowPty {
					req.Reply(false, nil)
					continue
				}
				sess.handlePtyReq(req)

			case "window-change":
				if sess.pty == nil {
					req.Reply(false, nil)
					continue
				}
				win, ok := parseWinchRequest(req.Payload)
				if ok {
					sess.pty.Window = win
					sess.winch <- win
				}
				req.Reply(ok, nil)
			case agentRequestType:
				if s.allowAgentFwd {

					atomic.StoreUint64(&sess.agentRequested, 1)
					req.Reply(true, nil)
				} else {
					req.Reply(false, nil)
				}
			default:
				// TODO: debug log
				req.Reply(false, nil)
			}
		default:
		}
	}
}

const (
	agentRequestType = "auth-agent-req@openssh.com"
	agentChannelType = "auth-agent@openssh.com"
)

type session struct {
	ssh.Channel
	handled        uint64
	exited         uint64
	agentRequested uint64

	conn    *ssh.ServerConn
	handler SessionHandler
	env     []string
	cmd     []string

	pty   *Pty
	winch chan Window

	signalChCh chan chan<- os.Signal
}

func (s *session) handle(ctx context.Context, req *ssh.Request) {
	if !atomic.CompareAndSwapUint64(&s.handled, 0, 1) {
		req.Reply(false, nil)
		return
	}
	req.Reply(true, nil)

	// Parse payload
	var payload = struct{ Value string }{}
	ssh.Unmarshal(req.Payload, &payload)
	s.cmd, _ = shlex.Split(payload.Value)

	// Run handler and exit when finished
	go s.Exit(s.handler(ctx, s))
}

func (s *session) hasBeenHandled() bool {
	return atomic.LoadUint64(&s.handled) == 1
}

func (s *session) Write(p []byte) (n int, err error) {
	if s.pty != nil {
		m := len(p)
		// normalize \n to \r\n when pty is accepted.
		// this is a hardcoded shortcut since we don't support terminal modes.
		p = bytes.Replace(p, []byte{'\n'}, []byte{'\r', '\n'}, -1)
		p = bytes.Replace(p, []byte{'\r', '\r', '\n'}, []byte{'\r', '\n'}, -1)
		n, err = s.Channel.Write(p)
		if n > m {
			n = m
		}
		return
	}
	return s.Channel.Write(p)
}

func (s *session) User() string {
	return s.conn.User()
}

func (s *session) Close() error {
	s.Channel.Close()
	s.conn.Close()
	return nil
}

func (s *session) LocalAddr() net.Addr {
	return s.conn.LocalAddr()
}

func (s *session) RemoteAddr() net.Addr {
	return s.conn.RemoteAddr()
}

func (s *session) Environ() []string {
	return append([]string(nil), s.env...)
}

func (s *session) Command() []string {
	return append([]string(nil), s.cmd...)
}

func (s *session) WriteString(msg string) (int, error) {
	return s.Write([]byte(msg))
}

func (s *session) Exit(code int) error {
	if !atomic.CompareAndSwapUint64(&s.exited, 0, 1) {
		return fmt.Errorf("exit called more than once")
	}

	status := struct{ Status uint32 }{uint32(code)}
	_, err := s.Channel.SendRequest("exit-status", false, ssh.Marshal(&status))
	if err != nil {
		return err
	}
	close(s.winch)
	s.Channel.Close()
	s.conn.Close()
	return nil
}

func (s *session) handlePtyReq(req *ssh.Request) {
	if s.hasBeenHandled() {
		req.Reply(false, nil)
		return
	} else if s.pty != nil {
		req.Reply(false, nil)
		return
	}

	ptyReq, ok := parsePtyRequest(req.Payload)
	if !ok {
		req.Reply(false, nil)
		return
	}
	s.pty = &ptyReq
	s.winch = make(chan Window, 1)
	s.winch <- ptyReq.Window
	req.Reply(ok, nil)
}

func (s *session) PublicKey() ssh.PublicKey {
	perms := s.conn.Permissions
	if perms == nil {
		return nil
	}
	if perms.Extensions == nil {
		return nil
	}

	if keyData, ok := perms.Extensions[permKeyData]; ok {
		if key, err := ssh.ParsePublicKey([]byte(keyData)); err == nil {
			return key
		}
	}
	return nil
}

func (s *session) Permissions() *ssh.Permissions {
	return s.conn.Permissions
}

func (s *session) Pty() (Pty, <-chan Window, bool) {
	if s.pty != nil {
		return *s.pty, s.winch, true
	}
	return Pty{}, s.winch, false
}

func (s *session) Signals(c chan<- os.Signal) {
	s.signalChCh <- c
}
