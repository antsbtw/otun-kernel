package hysteria2

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
)

// 用真实 quic-go 连接验证 RTT 样本判据（复测 2026-10-22：「收到对端的包」会被节点重传骗过）。
// 保活周期缩到 testKeepAlive，判定窗口按生产的比例（两轮保活 + 余量）缩放。

const (
	testKeepAlive   = 400 * time.Millisecond
	testQUICSettle  = 200 * time.Millisecond
	testQUICDeadine = testQUICSettle + 2*testKeepAlive + 400*time.Millisecond
)

// dropWriteConn 在 drop 置位后丢掉所有发出的包，模拟「客户端→节点」被掐断。
type dropWriteConn struct {
	net.PacketConn
	drop atomic.Bool
}

func (c *dropWriteConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.drop.Load() {
		return len(p), nil
	}
	return c.PacketConn.WriteTo(p, addr)
}

func testTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"test"}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, NextProtos: []string{"test"}}
}

// dialTestQUIC 起一对 quic 连接，返回客户端连接、服务端连接与客户端的丢包开关。
func dialTestQUIC(t *testing.T, ctx context.Context) (*quic.Conn, *quic.Conn, *dropWriteConn) {
	t.Helper()
	config := &quic.Config{KeepAlivePeriod: testKeepAlive, MaxIdleTimeout: 10 * time.Second}
	serverUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serverUDP.Close() })
	listener, err := quic.Listen(serverUDP, testTLSConfig(t), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	clientUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientUDP.Close() })
	clientPacketConn := &dropWriteConn{PacketConn: clientUDP}
	accepted := make(chan *quic.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept(ctx)
		if acceptErr == nil {
			accepted <- conn
		}
	}()
	clientConn, err := quic.Dial(ctx, clientPacketConn, serverUDP.LocalAddr(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"test"}}, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientConn.CloseWithError(0, "") })
	serverConn := <-accepted
	t.Cleanup(func() { _ = serverConn.CloseWithError(0, "") })
	<-clientConn.HandshakeComplete()
	// 等握手收尾（HANDSHAKE_DONE、ACK）完成，避免把它们算进各场景。
	time.Sleep(50 * time.Millisecond)
	return clientConn, serverConn, clientPacketConn
}

// ① 客户端→节点被掐断、节点持续向客户端发数据：客户端一直在收包，但不能判通过。
func TestDirectVerifyQUICOneWayCut(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	clientConn, serverConn, clientPacketConn := dialTestQUIC(t, ctx)
	clientPacketConn.drop.Store(true)
	stream, err := serverConn.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		payload := make([]byte, 512)
		for ctx.Err() == nil {
			if _, writeErr := stream.Write(payload); writeErr != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	before := clientConn.ConnectionStats().PacketsReceived
	result := waitDirectVerified(ctx, func() rttSample { return quicRTTSample(clientConn) }, testQUICSettle, testQUICDeadine, 20*time.Millisecond)
	if result != directUnverified {
		t.Fatalf("result = %v, want directUnverified（单向通被判可用）", result)
	}
	if after := clientConn.ConnectionStats().PacketsReceived; after <= before {
		t.Fatalf("PacketsReceived %d → %d：场景没构造出「客户端一直在收包」", before, after)
	}
}

// ② 健康的空闲连接：两侧保活周期相同、交替发 PING，两轮保活内必须判通过。
func TestDirectVerifyQUICHealthyIdle(t *testing.T) {
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		clientConn, _, _ := dialTestQUIC(t, ctx)
		result := waitDirectVerified(ctx, func() rttSample { return quicRTTSample(clientConn) }, testQUICSettle, testQUICDeadine, 20*time.Millisecond)
		cancel()
		if result != directVerified {
			t.Fatalf("round %d: result = %v, want directVerified（健康空闲连接被判失败）", i, result)
		}
	}
}

// ③ 健康的只收不发连接（下载）：客户端只回 ACK，靠每 19 个纯 ACK 带一个 PING 产生样本。
func TestDirectVerifyQUICHealthyDownload(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	clientConn, serverConn, _ := dialTestQUIC(t, ctx)
	stream, err := serverConn.OpenUniStream()
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		payload := make([]byte, 1000)
		for ctx.Err() == nil {
			if _, writeErr := stream.Write(payload); writeErr != nil {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	go func() {
		received, acceptErr := clientConn.AcceptUniStream(ctx)
		if acceptErr != nil {
			return
		}
		buffer := make([]byte, 4096)
		for {
			if _, readErr := received.Read(buffer); readErr != nil {
				return
			}
		}
	}()
	result := waitDirectVerified(ctx, func() rttSample { return quicRTTSample(clientConn) }, testQUICSettle, testQUICDeadine, 20*time.Millisecond)
	if result != directVerified {
		t.Fatalf("result = %v, want directVerified（健康下载连接被判失败）", result)
	}
}
