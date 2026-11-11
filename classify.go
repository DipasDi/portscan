package portscan

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
)

// Коды сетевых ошибок Windows
const (
	wsaECONNREFUSED syscall.Errno = 10061
	wsaENETDOWN     syscall.Errno = 10050
	wsaENETUNREACH  syscall.Errno = 10051
	wsaEHOSTDOWN    syscall.Errno = 10064
	wsaEHOSTUNREACH syscall.Errno = 10065
)

func classifyError(scanCtx context.Context, err error) State {

	if err == nil {
		return StateOpen
	}

	if scanCtx.Err() != nil || errors.Is(err, context.Canceled) {
		return StateCanceled
	}

	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return StateTimeout
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return StateTimeout
	}

	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {

		case syscall.ECONNREFUSED, wsaECONNREFUSED:
			return StateClosed

		case syscall.EHOSTUNREACH, syscall.ENETUNREACH, syscall.ENETDOWN, syscall.EHOSTDOWN,
			wsaEHOSTUNREACH, wsaENETUNREACH, wsaENETDOWN, wsaEHOSTDOWN:
			return StateUnreachable
		}
	}

	return StateError
}
