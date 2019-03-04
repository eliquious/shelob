package sshh

import (
	"context"
	"io/ioutil"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

// DefaultHandler is the default session handler.
var DefaultHandler SessionHandler

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
