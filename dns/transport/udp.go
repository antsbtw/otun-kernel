package transport

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio/deadline"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
)

var _ adapter.DNSTransport = (*UDPTransport)(nil)

// udpStallTimeout：查询第一次尝试等回包的时间，超过且会话上没有任何回包就换新会话重发。
const udpStallTimeout = 2 * time.Second

var errUDPSessionStalled = E.New("UDP session stalled")

func RegisterUDP(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.RemoteDNSServerOptions](registry, C.DNSTypeUDP, NewUDP)
}

type UDPTransport struct {
	dns.TransportAdapter
	logger logger.ContextLogger

	dialer     N.Dialer
	serverAddr M.Socksaddr
	udpSize    atomic.Int32

	connection *ConnPool[net.Conn]

	// 最近一次在共享会话上收到合法回包的时间（UnixNano），用来判断会话是否还活着。
	lastReceive atomic.Int64

	callbackAccess sync.RWMutex
	queryId        uint16
	callbacks      map[uint16]*udpCallback
}

type udpCallback struct {
	access   sync.Mutex
	response *mDNS.Msg
	done     chan struct{}
}

func NewUDP(ctx context.Context, logger log.ContextLogger, tag string, options option.RemoteDNSServerOptions) (adapter.DNSTransport, error) {
	transportDialer, err := dns.NewRemoteDialer(ctx, options)
	if err != nil {
		return nil, err
	}
	serverAddr := options.DNSServerAddressOptions.Build()
	if serverAddr.Port == 0 {
		serverAddr.Port = 53
	}
	if !serverAddr.IsValid() {
		return nil, E.New("invalid server address: ", serverAddr)
	}
	return NewUDPRaw(logger, dns.NewTransportAdapterWithRemoteOptions(C.DNSTypeUDP, tag, options), transportDialer, serverAddr), nil
}

func NewUDPRaw(logger logger.ContextLogger, adapter dns.TransportAdapter, dialerInstance N.Dialer, serverAddr M.Socksaddr) *UDPTransport {
	t := &UDPTransport{
		TransportAdapter: adapter,
		logger:           logger,
		dialer:           dialerInstance,
		serverAddr:       serverAddr,
		callbacks:        make(map[uint16]*udpCallback),
		connection: NewConnPool(ConnPoolOptions[net.Conn]{
			Mode: ConnPoolSingle,
			IsAlive: func(conn net.Conn) bool {
				return conn != nil
			},
			Close: func(conn net.Conn, cause error) {
				conn.Close()
			},
		}),
	}
	t.udpSize.Store(2048)
	return t
}

func (t *UDPTransport) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	return dialer.InitializeDetour(t.dialer)
}

func (t *UDPTransport) Close() error {
	return t.connection.Close()
}

func (t *UDPTransport) Reset() {
	t.connection.Reset()
}

func (t *UDPTransport) nextAvailableQueryId() (uint16, error) {
	start := t.queryId
	for {
		t.queryId++
		if _, exists := t.callbacks[t.queryId]; !exists {
			return t.queryId, nil
		}
		if t.queryId == start {
			return 0, E.New("no available query ID")
		}
	}
}

func (t *UDPTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	response, err := t.exchange(ctx, message)
	if err != nil {
		return nil, err
	}
	if response.Truncated {
		t.logger.InfoContext(ctx, "response truncated, retrying with TCP")
		return t.exchangeTCP(ctx, message)
	}
	return response, nil
}

func (t *UDPTransport) exchangeTCP(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	conn, err := t.dialer.DialContext(ctx, N.NetworkTCP, t.serverAddr)
	if err != nil {
		return nil, E.Cause(err, "dial TCP connection")
	}
	defer conn.Close()
	defer setConnDeadline(ctx, conn, deadline.NeedAdditionalReadDeadline(conn))()
	err = WriteMessage(conn, message.Id, message)
	if err != nil {
		return nil, E.Cause(err, "write request")
	}
	response, err := ReadMessage(conn)
	if err != nil {
		return nil, E.Cause(err, "read response")
	}
	return response, nil
}

func (t *UDPTransport) exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	if edns0Opt := message.IsEdns0(); edns0Opt != nil {
		udpSize := int32(edns0Opt.UDPSize())
		for {
			current := t.udpSize.Load()
			if udpSize <= current {
				break
			}
			if t.udpSize.CompareAndSwap(current, udpSize) {
				t.Reset()
				break
			}
		}
	}

	// 共享会话被中途静默掐断时（NAT 过期、路径断了），读写不会报错，要等 TCP keepalive
	// 十几分钟后才发现，期间每个查询都超时。所以第一次尝试 udpStallTimeout 内没有回包、
	// 会话上也没收到过任何回包，就作废会话，在新会话上重发一次。重发只有一次，
	// 新会话上不再按 udpStallTimeout 作废，避免网络整体不通时不停新建会话。
	response, retry, err := t.exchangeAttempt(ctx, message, true)
	if !retry {
		return response, err
	}
	t.logger.InfoContext(ctx, "UDP session stalled or closed, retrying on a new session")
	response, _, err = t.exchangeAttempt(ctx, message, false)
	return response, err
}

// exchangeAttempt 在共享会话上发一次查询。firstAttempt 时：
//   - 写失败、udpStallTimeout 内会话无任何回包、或会话被其他查询 / 读错误作废，都返回 retry=true，由调用方在新会话上重发；
//   - 会话在本查询发出后收到过别的回包，说明会话活着，只是这个查询的上游慢，继续等到 ctx 结束。
func (t *UDPTransport) exchangeAttempt(ctx context.Context, message *mDNS.Msg, firstAttempt bool) (*mDNS.Msg, bool, error) {
	conn, connCtx, created, err := t.connection.AcquireShared(ctx, func(ctx context.Context) (net.Conn, error) {
		rawConn, err := t.dialer.DialContext(ctx, N.NetworkUDP, t.serverAddr)
		if err != nil {
			return nil, E.Cause(err, "dial UDP connection")
		}
		return rawConn, nil
	})
	if err != nil {
		return nil, false, err
	}
	if created {
		go t.recvLoop(conn)
	}

	callback := &udpCallback{
		done: make(chan struct{}),
	}

	t.callbackAccess.Lock()
	queryId, err := t.nextAvailableQueryId()
	if err != nil {
		t.callbackAccess.Unlock()
		t.connection.Release(conn, true)
		return nil, false, err
	}
	t.callbacks[queryId] = callback
	t.callbackAccess.Unlock()

	defer func() {
		t.callbackAccess.Lock()
		delete(t.callbacks, queryId)
		t.callbackAccess.Unlock()
	}()

	buffer := buf.NewSize(1 + message.Len())
	defer buffer.Release()

	exMessage := *message
	exMessage.Compress = true
	originalId := message.Id
	exMessage.Id = queryId

	rawMessage, err := exMessage.PackBuffer(buffer.FreeBytes())
	if err != nil {
		return nil, false, err
	}

	sentAt := time.Now().UnixNano()
	_, err = conn.Write(rawMessage)
	if err != nil {
		t.connection.Invalidate(conn, err)
		if firstAttempt {
			return nil, true, nil
		}
		return nil, false, E.Cause(err, "write request")
	}

	var stall <-chan time.Time
	if firstAttempt {
		timer := time.NewTimer(udpStallTimeout)
		defer timer.Stop()
		stall = timer.C
	}

	for {
		select {
		case <-callback.done:
			t.connection.Release(conn, true)
			callback.response.Id = originalId
			return callback.response, false, nil
		case <-stall:
			stall = nil
			if callbackDone(callback) || t.lastReceive.Load() > sentAt {
				continue
			}
			t.connection.Invalidate(conn, errUDPSessionStalled)
			return nil, true, nil
		case <-connCtx.Done():
			if callbackDone(callback) {
				callback.response.Id = originalId
				return callback.response, false, nil
			}
			if firstAttempt && ctx.Err() == nil {
				return nil, true, nil
			}
			return nil, false, context.Cause(connCtx)
		case <-ctx.Done():
			t.connection.Release(conn, true)
			return nil, false, ctx.Err()
		}
	}
}

// callbackDone：回包和计时器 / 会话作废同时到达时，select 可能先选中后者，先看一眼回包到没到。
func callbackDone(callback *udpCallback) bool {
	select {
	case <-callback.done:
		return true
	default:
		return false
	}
}

func (t *UDPTransport) recvLoop(conn net.Conn) {
	for {
		buffer := buf.NewSize(int(t.udpSize.Load()))
		_, err := buffer.ReadOnceFrom(conn)
		if err != nil {
			buffer.Release()
			t.connection.Invalidate(conn, err)
			return
		}

		var message mDNS.Msg
		err = message.Unpack(buffer.Bytes())
		buffer.Release()
		if err == nil {
			t.lastReceive.Store(time.Now().UnixNano())
		}
		if err != nil {
			t.logger.Debug("discarded malformed UDP response: ", err)
			continue
		}

		t.callbackAccess.RLock()
		callback, loaded := t.callbacks[message.Id]
		t.callbackAccess.RUnlock()

		if !loaded {
			continue
		}

		callback.access.Lock()
		select {
		case <-callback.done:
		default:
			callback.response = &message
			close(callback.done)
		}
		callback.access.Unlock()
	}
}
