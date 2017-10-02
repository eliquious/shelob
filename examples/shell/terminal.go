package main

import (
	"context"
	"fmt"
	"strings"

	log "github.com/mgutz/logxi/v1"

	"github.com/blacklabeldata/sshh"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
	// tomb "gopkg.in/tomb.v2"
)

func NewShellHandler(logger log.Logger) sshh.Handler {
	return &shellHandler{logger}
}

type shellHandler struct {
	logger log.Logger
}

func (s *shellHandler) Handle(ctx *sshh.Context) error {
	// ctx context.Context, sshConn *ssh.ServerConn, channel ssh.Channel, requests <-chan *ssh.Request
	defer ctx.Channel.Close()
	s.logger.Info("WooHoo!!! Inside Handler!")

	// Create tomb for terminal goroutines
	// var t tomb.Tomb

	// Sessions have out-of-band requests such as "shell",
	// "pty-req" and "env".  Here we handle only the
	// "shell" request.
	// t.Go(func() error {
OUTER:
	for {
		select {
		case <-ctx.Context.Done():
			// t.Kill(nil)
			break OUTER
		case req := <-ctx.Requests:
			if req == nil {
				break OUTER
			}

			ok := false
			switch req.Type {
			case "shell":
				ok = true

				if len(req.Payload) > 0 {
					// fmt.Println(string(req.Payload))

					// We don't accept any
					// commands, only the
					// default shell.
					ok = false
				}

			case "pty-req":
				// Responding 'ok' here will let the client
				// know we have a pty ready for input
				ok = true

				go s.startTerminal(ctx.Context, ctx.Connection, ctx.Channel)
				// t.Go(func() error {
				// })
			}

			req.Reply(ok, nil)
		}
	}
	return nil
	// })
	// return t.Wait()
	// return nil
}

func (s *shellHandler) startTerminal(ctx context.Context, sshConn *ssh.ServerConn, channel ssh.Channel) error {
	defer channel.Close()

	prompt := ">>> "
	term := terminal.NewTerminal(channel, prompt)

	// // Try to make the terminal raw
	// oldState, err := terminal.MakeRaw(0)
	// if err != nil {
	//     logger.Warn("Error making terminal raw: ", err.Error())
	// }
	// defer terminal.Restore(0, oldState)

	// Get username
	username, ok := sshConn.Permissions.Extensions["username"]
	if !ok {
		username = "user"
	}

	// Write ascii text
	term.Write([]byte(fmt.Sprintf("\r\n Nice job, %s! You are connected!\r\n", username)))
	defer term.Write([]byte(fmt.Sprintf("\r\nGoodbye, %s!\r\n", username)))

	// Start REPL
	for {

		select {
		case <-ctx.Done():
			return nil
		default:
			s.logger.Info("Reading line...")
			input, err := term.ReadLine()
			if err != nil {
				fmt.Errorf("Readline() error")
				return err
			}

			// Process line
			line := strings.TrimSpace(input)
			if len(line) > 0 {

				// Log input and handle exit requests
				if line == "exit" || line == "quit" {
					s.logger.Info("Closing connection")
					return nil
				}

				// Echo input
				channel.Write(term.Escape.Green)
				channel.Write([]byte(line + "\r\n"))
				channel.Write(term.Escape.Reset)
			}
		}
	}
	return nil
}
