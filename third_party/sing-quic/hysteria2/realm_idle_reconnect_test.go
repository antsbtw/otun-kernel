package hysteria2

import (
	"context"
	"errors"
	"testing"

	"github.com/sagernet/quic-go"
)

func runIdleReconnect(t *testing.T, cause error, current bool) bool {
	t.Helper()
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(cause)
	reconnected := false
	idleReconnect(ctx, func() bool { return current }, func() { reconnected = true })
	return reconnected
}

func TestIdleReconnectOnIdleTimeout(t *testing.T) {
	if !runIdleReconnect(t, &quic.IdleTimeoutError{}, true) {
		t.Fatal("did not reconnect after idle timeout")
	}
}

// quic-go 可能把关闭原因包一层，errors.As 仍应认出空闲超时。
func TestIdleReconnectOnWrappedIdleTimeout(t *testing.T) {
	cause := errors.Join(errors.New("outer"), &quic.IdleTimeoutError{})
	if !runIdleReconnect(t, cause, true) {
		t.Fatal("did not reconnect after wrapped idle timeout")
	}
}

func TestIdleReconnectIgnoresOtherCloses(t *testing.T) {
	for _, cause := range []error{
		errors.New("realm: connection stalled"),
		&quic.ApplicationError{Remote: true},
		context.Canceled,
	} {
		if runIdleReconnect(t, cause, true) {
			t.Fatalf("reconnected after non-idle close: %v", cause)
		}
	}
}

func TestIdleReconnectSkipsReplacedOrClosedClient(t *testing.T) {
	if runIdleReconnect(t, &quic.IdleTimeoutError{}, false) {
		t.Fatal("reconnected for a connection that is no longer current")
	}
}
