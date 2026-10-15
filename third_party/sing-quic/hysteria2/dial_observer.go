package hysteria2

import (
	"net/netip"

	"github.com/sagernet/sing-quic/hysteria2/realm"
)

// dialObserver 包一层 realm.DialObserver:内部为 nil 时全部 no-op,调用点不用判空。
type dialObserver struct {
	inner realm.DialObserver
}

func (c *Client) newDialObserver() dialObserver {
	if c.realmOptions == nil || c.realmOptions.NewDialObserver == nil {
		return dialObserver{}
	}
	return dialObserver{inner: c.realmOptions.NewDialObserver()}
}

func (o dialObserver) STUNDiscovered(localAddresses []netip.AddrPort) {
	if o.inner != nil {
		o.inner.STUNDiscovered(localAddresses)
	}
}

func (o dialObserver) RendezvousDone(peerAddresses []netip.AddrPort, metadata realm.PunchMetadata) {
	if o.inner != nil {
		o.inner.RendezvousDone(peerAddresses, metadata)
	}
}

func (o dialObserver) PunchAttempted(family string, candidates []netip.AddrPort) {
	if o.inner != nil {
		o.inner.PunchAttempted(family, candidates)
	}
}

func (o dialObserver) PunchSucceeded(family string, result realm.PunchResult) {
	if o.inner != nil {
		o.inner.PunchSucceeded(family, result)
	}
}

func (o dialObserver) RelaySettled(relayAddr string, err error) {
	if o.inner != nil {
		o.inner.RelaySettled(relayAddr, err)
	}
}

func (o dialObserver) HandshakeDone() {
	if o.inner != nil {
		o.inner.HandshakeDone()
	}
}

func (o dialObserver) Failed(stage string, err error) {
	if o.inner != nil {
		o.inner.Failed(stage, err)
	}
}

func (o dialObserver) Finish() {
	if o.inner != nil {
		o.inner.Finish()
	}
}
