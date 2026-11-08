package transport

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// stallServer 是本地 UDP DNS 服务器：按客户端源地址区分会话，可以让指定会话「静默掐断」
// （收包不回），也可以让指定域名延迟回答。
type stallServer struct {
	conn net.PacketConn

	access    sync.Mutex
	sessions  []string     // 按出现顺序记录的客户端源地址
	blackhole map[int]bool // 会话序号（从 0 开始）→ 不回包
	dropAll   bool         // 所有会话都不回包
	delay     map[string]time.Duration
}

func newStallServer(t *testing.T) *stallServer {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	s := &stallServer{conn: conn, blackhole: map[int]bool{}, delay: map[string]time.Duration{}}
	t.Cleanup(func() { conn.Close() })
	go s.serve()
	return s
}

func (s *stallServer) serve() {
	buffer := make([]byte, 4096)
	for {
		n, addr, err := s.conn.ReadFrom(buffer)
		if err != nil {
			return
		}
		var request mDNS.Msg
		if request.Unpack(buffer[:n]) != nil || len(request.Question) == 0 {
			continue
		}
		s.access.Lock()
		index := -1
		for i, session := range s.sessions {
			if session == addr.String() {
				index = i
			}
		}
		if index < 0 {
			s.sessions = append(s.sessions, addr.String())
			index = len(s.sessions) - 1
		}
		drop := s.dropAll || s.blackhole[index]
		delay := s.delay[request.Question[0].Name]
		s.access.Unlock()
		if drop {
			continue
		}
		response := new(mDNS.Msg)
		response.SetReply(&request)
		response.Answer = append(response.Answer, &mDNS.A{
			Hdr: mDNS.RR_Header{Name: request.Question[0].Name, Rrtype: mDNS.TypeA, Class: mDNS.ClassINET, Ttl: 60},
			A:   net.IPv4(1, 2, 3, 4),
		})
		raw, _ := response.Pack()
		go func() {
			time.Sleep(delay)
			s.conn.WriteTo(raw, addr)
		}()
	}
}

func (s *stallServer) set(update func(s *stallServer)) {
	s.access.Lock()
	defer s.access.Unlock()
	update(s)
}

func (s *stallServer) sessionCount() int {
	s.access.Lock()
	defer s.access.Unlock()
	return len(s.sessions)
}

// countingDialer 用真实 UDP 套接字拨号，并记录拨号次数（= 新建会话次数）。
type countingDialer struct {
	dials atomic.Int32
}

func (d *countingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.dials.Add(1)
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, destination.String())
}

func (d *countingDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return net.ListenPacket("udp", "127.0.0.1:0")
}

func newStallTestTransport(t *testing.T, server *stallServer) (*UDPTransport, *countingDialer) {
	dialer := &countingDialer{}
	transport := NewUDPRaw(
		log.NewNOPFactory().Logger(),
		dns.NewTransportAdapter(C.DNSTypeUDP, "test", nil),
		dialer,
		M.SocksaddrFromNet(server.conn.LocalAddr()),
	)
	t.Cleanup(func() { transport.Close() })
	return transport, dialer
}

func query(name string) *mDNS.Msg {
	message := new(mDNS.Msg)
	message.SetQuestion(mDNS.Fqdn(name), mDNS.TypeA)
	return message
}

func exchangeWithTimeout(transport *UDPTransport, name string, timeout time.Duration) (*mDNS.Msg, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return transport.Exchange(ctx, query(name))
}

// 正常情况：一个会话，不重发。
func TestUDPHealthySessionNoRetry(t *testing.T) {
	server := newStallServer(t)
	transport, dialer := newStallTestTransport(t, server)

	for i := 0; i < 3; i++ {
		response, err := exchangeWithTimeout(transport, "ok.example", 5*time.Second)
		require.NoError(t, err)
		require.Len(t, response.Answer, 1)
	}
	require.EqualValues(t, 1, dialer.dials.Load())
}

// 会话被静默掐断：约 2 秒后换新会话重发并成功。
func TestUDPStalledSessionRetriesOnNewSession(t *testing.T) {
	server := newStallServer(t)
	server.set(func(s *stallServer) { s.blackhole[0] = true })
	transport, dialer := newStallTestTransport(t, server)

	start := time.Now()
	response, err := exchangeWithTimeout(transport, "stall.example", 10*time.Second)
	elapsed := time.Since(start)
	require.NoError(t, err)
	require.Len(t, response.Answer, 1)
	require.GreaterOrEqual(t, elapsed, udpStallTimeout)
	require.Less(t, elapsed, udpStallTimeout+time.Second)
	require.EqualValues(t, 2, dialer.dials.Load())

	// 之后的查询直接走新会话，不再等。
	start = time.Now()
	_, err = exchangeWithTimeout(transport, "after.example", 5*time.Second)
	require.NoError(t, err)
	require.Less(t, time.Since(start), 500*time.Millisecond)
	require.EqualValues(t, 2, dialer.dials.Load())
}

// 同一会话上还在等的其他查询也要在新会话上重发，而且只新建一个会话。
func TestUDPPendingQueriesRetriedTogether(t *testing.T) {
	server := newStallServer(t)
	server.set(func(s *stallServer) { s.blackhole[0] = true })
	transport, dialer := newStallTestTransport(t, server)

	names := []string{"a.example", "b.example", "c.example", "d.example"}
	var wg sync.WaitGroup
	errs := make([]error, len(names))
	start := time.Now()
	for i, name := range names {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			_, errs[i] = exchangeWithTimeout(transport, name, 10*time.Second)
		}(i, name)
		time.Sleep(300 * time.Millisecond)
	}
	wg.Wait()
	for i, err := range errs {
		require.NoError(t, err, names[i])
	}
	// 第一个查询 2 秒后作废会话，其余查询随即在同一个新会话上重发。
	require.Less(t, time.Since(start), udpStallTimeout+time.Second)
	require.EqualValues(t, 2, dialer.dials.Load())
	require.Equal(t, 2, server.sessionCount())
}

// 会话活着、只是某个域名上游慢：其他查询有回包，不作废会话，也不重发。
func TestUDPAliveSessionNotInvalidatedBySlowQuery(t *testing.T) {
	server := newStallServer(t)
	server.set(func(s *stallServer) { s.delay["slow.example."] = 3 * time.Second })
	transport, dialer := newStallTestTransport(t, server)

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := exchangeWithTimeout(transport, "slow.example", 10*time.Second)
		done <- err
	}()
	for i := 0; i < 4; i++ {
		time.Sleep(400 * time.Millisecond)
		_, err := exchangeWithTimeout(transport, "fast.example", 5*time.Second)
		require.NoError(t, err)
	}
	require.NoError(t, <-done)
	require.GreaterOrEqual(t, time.Since(start), 3*time.Second)
	require.EqualValues(t, 1, dialer.dials.Load())
}

// 网络整体不通：只重发一次，新会话上不再按 2 秒作废，最终按超时失败。
func TestUDPRetryOnlyOnce(t *testing.T) {
	server := newStallServer(t)
	server.set(func(s *stallServer) { s.dropAll = true })
	transport, dialer := newStallTestTransport(t, server)

	start := time.Now()
	_, err := exchangeWithTimeout(transport, "dead.example", 6*time.Second)
	require.Error(t, err)
	require.GreaterOrEqual(t, time.Since(start), 6*time.Second)
	require.EqualValues(t, 2, dialer.dials.Load())
}
