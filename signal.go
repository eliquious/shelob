package sshh

import (
	"fmt"
	"os"
	"syscall"
)

// POSIX signals as listed in RFC 4254 Section 6.10.
const (
	SIGABRT = "ABRT"
	SIGALRM = "ALRM"
	SIGFPE  = "FPE"
	SIGHUP  = "HUP"
	SIGILL  = "ILL"
	SIGINT  = "INT"
	SIGKILL = "KILL"
	SIGPIPE = "PIPE"
	SIGQUIT = "QUIT"
	SIGSEGV = "SEGV"
	SIGTERM = "TERM"
	SIGUSR1 = "USR1"
	SIGUSR2 = "USR2"
)

func toSignal(sig string) (os.Signal, error) {
	switch string(sig) {
	case SIGABRT:
		return syscall.SIGABRT, nil
	case SIGALRM:
		return syscall.SIGALRM, nil
	case SIGFPE:
		return syscall.SIGFPE, nil
	case SIGHUP:
		return syscall.SIGHUP, nil
	case SIGILL:
		return syscall.SIGILL, nil
	case SIGINT:
		return syscall.SIGINT, nil
	case SIGKILL:
		return syscall.SIGKILL, nil
	case SIGPIPE:
		return syscall.SIGPIPE, nil
	case SIGQUIT:
		return syscall.SIGQUIT, nil
	case SIGSEGV:
		return syscall.SIGSEGV, nil
	case SIGTERM:
		return syscall.SIGTERM, nil
	case SIGUSR1:
		return syscall.SIGUSR1, nil
	case SIGUSR2:
		return syscall.SIGUSR2, nil
	default:
		return nil, fmt.Errorf("unknown signal")
	}
}
