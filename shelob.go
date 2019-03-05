package shelob

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

// DefaultHandler is the default session handler.
var DefaultHandler SessionHandler = func(_ context.Context, s Session) int {
	return 0
}

// Handle sets the default handler.
func Handle(h SessionHandler) {
	DefaultHandler = h
}

// OptionFunc modifies the default config options.
type OptionFunc func(*Config) error

// ListenAndServe starts the server with the options.
func ListenAndServe(addr string, opts ...OptionFunc) error {
	conf := &Config{
		Addr:            addr,
		MaxDeadline:     time.Second,
		RequestHandlers: map[string]RequestHandler{},
		ChannelHandlers: map[string]ChannelHandler{},
		ServerConfig:    &ssh.ServerConfig{},
	}

	// Verify shell handler
	if _, ok := conf.ChannelHandlers["session"]; !ok {
		conf.ChannelHandlers["session"] = NewSessionChannelHandler(DefaultHandler, true, false)
	}

	// Read opts
	for _, opt := range opts {
		if err := opt(conf); err != nil {
			return err
		}
	}

	// Create and start server
	ctx := context.Background()
	srv, err := New(ctx, conf)
	if err != nil {
		return err
	}
	return srv.ListenAndServe()
}

func WithMaxConnections(conns int) OptionFunc {
	return func(conf *Config) error {
		conf.MaxConnections = conns
		return nil
	}
}

func WithMaxClientConnections(conns int) OptionFunc {
	return func(conf *Config) error {
		conf.MaxClientConnections = conns
		return nil
	}
}

func WithMaxDeadline(deadline time.Duration) OptionFunc {
	return func(conf *Config) error {
		conf.MaxDeadline = deadline
		return nil
	}
}

func WithMaxConnectionDuration(timeout time.Duration) OptionFunc {
	return func(conf *Config) error {
		conf.MaxConnectionDuration = timeout
		return nil
	}
}

func WithRequestHandler(reqType string, handler RequestHandler) OptionFunc {
	return func(conf *Config) error {
		conf.RequestHandlers[reqType] = handler
		return nil
	}
}

func WithChannelHandler(chType string, handler ChannelHandler) OptionFunc {
	return func(conf *Config) error {
		conf.ChannelHandlers[chType] = handler
		return nil
	}
}

func WithConnectionCallback(fn func(net.Conn) net.Conn) OptionFunc {
	return func(conf *Config) error {
		conf.ConnectionCallback = fn
		return nil
	}
}

func WithEventHandler(handler EventHandler) OptionFunc {
	return func(conf *Config) error {
		conf.EventHandler = handler
		return nil
	}
}

func WithHostKey(signer ssh.Signer) OptionFunc {
	return func(conf *Config) error {
		conf.PrivateKey = signer
		return nil
	}
}

func WithHostKeyFile(filepath string) OptionFunc {
	return func(conf *Config) error {

		pem, err := ioutil.ReadFile(filepath)
		if err != nil {
			return err
		}

		signer, err := ssh.ParsePrivateKey(pem)
		if err != nil {
			return err
		}

		conf.PrivateKey = signer
		return nil
	}
}

func WithSignalCh(ch chan os.Signal) OptionFunc {
	return func(conf *Config) error {
		conf.SignalChan = ch
		return nil
	}
}

func WithServerConfig(c *ssh.ServerConfig) OptionFunc {
	return func(conf *Config) error {
		conf.ServerConfig = c
		return nil
	}
}

func WithPasswordAuth(user, password string) OptionFunc {
	return func(conf *Config) error {
		if conf.ServerConfig == nil {
			return fmt.Errorf("err: server config is nil")
		}

		conf.ServerConfig.PasswordCallback = func(conn ssh.ConnMetadata, pw []byte) (perm *ssh.Permissions, err error) {
			if conn.User() == user && string(pw) == password {
				return &ssh.Permissions{}, nil
			} else {
				err = fmt.Errorf("Invalid username or password")
			}
			return
		}
		return nil
	}
}

func WithPublicKeyAuth(pubkey ssh.PublicKey) OptionFunc {
	return func(conf *Config) error {
		if conf.ServerConfig == nil {
			return fmt.Errorf("err: server config is nil")
		}

		wantedFingerprint := ssh.FingerprintLegacyMD5(pubkey)
		conf.ServerConfig.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (perm *ssh.Permissions, err error) {
			fingerprint := ssh.FingerprintLegacyMD5(key)
			if fingerprint != wantedFingerprint {
				return nil, fmt.Errorf("error: unauthorized")
			}

			perm = &ssh.Permissions{
				Extensions: map[string]string{
					permKeyType:        key.Type(),
					permKeyData:        string(key.Marshal()),
					permKeyFingerprint: fingerprint,
				},
			}
			return perm, nil
		}
		return nil
	}
}

func WithAuthLogCallback(cb func(conn ssh.ConnMetadata, method string, err error)) OptionFunc {
	return func(conf *Config) error {
		if conf.ServerConfig == nil {
			return fmt.Errorf("err: server config is nil")
		}

		conf.ServerConfig.AuthLogCallback = cb
		return nil
	}
}

func WithNoClientAuth() OptionFunc {
	return func(conf *Config) error {
		if conf.ServerConfig == nil {
			return fmt.Errorf("err: server config is nil")
		}
		conf.ServerConfig.NoClientAuth = true
		return nil
	}
}
