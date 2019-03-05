package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/eliquious/shelob"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

var privateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDjzAhRGLLcnQhs7Xe/2TrbjpHOkeBwVfmI0z+mZot87AXyIVcr
+OepPl/8UekPb352bz3zAwn2x5zCT/hW+1CBwp6fqhAvlxlYFEYr40L2dYKMmZyT
3kq18P3fTmAIKyXv7XOtVXiNLHc0Ai+3aN4J+yHKwbf42nNU3Qb1NRp9KQIDAQAB
AoGANgZyxoD8EpRvph3fs7FaYy356KryNtI9HzUyuE1DsbnsYxODMBuVHa98ZkQq
6Q1BSedyIstKtqt6wx7iQAbUfa9VxYht2DnxJDG7AhbQS1jd8ifSPCyhsp7HqCL5
pPbJBoW2M2qVL95+TMaZKYDDQcpFIHsEzJ/6lnWatGdBxfECQQDwv+cFSe5i8hqU
5BmLH3131ez5jO4yCziQxNwZaEavDXPDsqeKl/8Oj9EOcVyysyOLR9z7NzOCV2wX
8u0hpO69AkEA8joVv2rZdb+83Zc1UF/qnihMt4ZqYafPMXEtl2YTZtDmQOZG0kMw
a/iPjkUt/t8+CNR/Z5RLUYA5NVJSlsI03QJBANUZaEo8KLCYkILebOXCl/Ks/zfd
UTIm0IkEV7Z9oKNuitvclYSOCgw/rNLV8TGUc4/jqm0LbaKf82Q3eULglRkCQBsi
4rjVEZOdbV0tyW09sZ0SSrXsuxJBqHaThVYGu3mzQXhX0+tOV6hg6kQ3/9Uj0WFP
3Q4PkPiKct5EYLg+/YkCQCpHiRgfbESG2J/eYtTdyDvm+r0m0pc4vitqKsRGjd2u
LZxh0eGWnXXd+Os/wOVMSzkAWuzc4VTxMUnk/yf13IA=
-----END RSA PRIVATE KEY-----
`

func main() {

	// Create logger
	logger := log.New(os.Stderr, "", log.LstdFlags|log.Lmicroseconds)

	// Get private key
	privateKey, err := ssh.ParsePrivateKey([]byte(privateKey))
	if err != nil {
		logger.Fatalf("Private key could not be parsed err=%s", err.Error())
	}

	// Handle signals
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	// Setup server config
	config := shelob.Config{
		Addr:         ":9022",
		MaxDeadline:  5 * time.Second,
		PrivateKey:   privateKey,
		SignalChan:   sig,
		EventHandler: shelob.LoggingEventHandler(logger),
		ChannelHandlers: map[string]shelob.ChannelHandler{
			"session": shelob.NewSessionChannelHandler(func(ctx context.Context, s shelob.Session) int {

				prompt := ">>> "
				term := terminal.NewTerminal(s, prompt)

				// Get username
				username := s.User()

				// Write ascii text
				term.Write([]byte(fmt.Sprintf("\r\n Nice job, %s! You are connected!\r\n", username)))
				defer term.Write([]byte(fmt.Sprintf("\r\nGoodbye, %s!\r\n", username)))

				logf := func(msg string, args ...interface{}) {
					// Make Terminal raw
					oldState, err := terminal.MakeRaw(0)
					if err != nil {
						return
					}
					defer terminal.Restore(0, oldState)
					logger.Printf(msg+"\r\n", args...)
				}

				// Start REPL
				for {

					select {
					case <-ctx.Done():
						return 0
					default:
						logf("Reading line...")
						input, err := term.ReadLine()
						if err != nil {
							return 1
						}

						// Process line
						line := strings.TrimSpace(input)
						if len(line) > 0 {

							// Log input and handle exit requests
							if line == "exit" || line == "quit" {
								logf("Closing connection")
								return 0
							}

							// Echo input
							s.Write(term.Escape.Green)
							s.Write([]byte(line + "\r\n"))
							s.Write(term.Escape.Reset)
						}
					}
				}
			}, true, false),
		},
		ServerConfig: &ssh.ServerConfig{
			PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (perm *ssh.Permissions, err error) {
				if conn.User() == "admin" && string(password) == "password" {

					// Add username to permissions
					perm = &ssh.Permissions{
						Extensions: map[string]string{
							"username": conn.User(),
						},
					}
				} else {
					err = fmt.Errorf("Invalid username or password")
				}
				return
			},
			AuthLogCallback: func(conn ssh.ConnMetadata, method string, err error) {
				if err == nil {
					logger.Printf("Successful login: user=%s method=%s\n", conn.User(), method)
				}
			},
			PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (perm *ssh.Permissions, err error) {
				return nil, fmt.Errorf("Unauthorized")
			},
		},
	}

	// Create SSH server
	sshServer, err := shelob.New(context.Background(), &config)
	if err != nil {
		logger.Fatalf("SSH Server could not be configured error=%s", err.Error())
	}

	// Start servers
	if err := sshServer.ListenAndServe(); err != nil {
		logger.Printf("Server exited error=%s", err.Error())
	}
}
