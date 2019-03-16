package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/eliquious/shelob"
	"golang.org/x/crypto/ssh"
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

	// Parse private key
	privateKey, err := ssh.ParsePrivateKey([]byte(privateKey))
	if err != nil {
		logger.Fatalf("Private key could not be parsed err=%s", err.Error())
	}

	shelob.Handle(func(ctx context.Context, s shelob.Session) int {
		s.WriteString("\nThe world changed, and a single moment of time was filled with an hour of thought.\n\n")
		s.WriteString(fmt.Sprintf("\nCommand: %q\n", s.Command()))
		return 0
	})

	opts := []shelob.OptionFunc{
		shelob.WithHostKey(privateKey),
		shelob.WithPasswordAuth("admin", "password"),
		shelob.WithEventHandler(shelob.LoggingEventHandler(logger)),
	}
	if err := shelob.ListenAndServe(":10022", opts...); err != nil {
		logger.Fatalf("Server exited with error err=%s", err.Error())
	}
}
