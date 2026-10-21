package realm

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

// 这些测试针对客户端「假成功」修复（KR2，2026-10-21）：Punch 收到节点的 Hello 只证明
// 「节点→客户端」单向可达，必须收到节点对我方 Hello 的 Ack 才能宣告成功。

// fakePeer 模拟节点：主动发 Hello；ackHellos=true 时对收到的 Hello 回 Ack。
func fakePeer(t *testing.T, ctx context.Context, peer *net.UDPConn, client netip.AddrPort, meta PunchMetadata, ackHellos bool) {
	t.Helper()
	hello, _ := EncodePunchPacket(PunchHello, meta)
	ack, _ := EncodePunchPacket(PunchAck, meta)
	go func() {
		ticker := time.NewTicker(punchInterval)
		defer ticker.Stop()
		for {
			_, _ = peer.WriteToUDPAddrPort(hello, client)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := peer.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			packetType, decodeErr := DecodePunchPacket(buf[:n], meta)
			if decodeErr == nil && packetType == PunchHello && ackHellos {
				_, _ = peer.WriteToUDPAddrPort(ack, from)
			}
		}
	}()
}

// ① 单向洞：节点的 Hello 能到，客户端的包到不了节点（节点从不回 Ack）。
// 修复前收到第一个 Hello 就返回成功；修复后必须在确认窗口后失败，且远早于 punchTimeout。
func TestPunchRejectsOneWayHole(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	meta := testMetadata()
	client, clientAddr := mustUDP(t)
	defer client.Close()
	peer, peerAddr := mustUDP(t)
	defer peer.Close()
	fakePeer(t, ctx, peer, clientAddr, meta, false)

	start := time.Now()
	_, err := Punch(ctx, client, []netip.AddrPort{peerAddr}, meta)
	if err == nil {
		t.Fatal("单向洞被判成功 —— 客户端假成功回归了")
	}
	if elapsed := time.Since(start); elapsed > punchConfirmWindow+time.Second {
		t.Fatalf("单向洞判失败耗时 %v，应在确认窗口 %v 附近", elapsed, punchConfirmWindow)
	}
}

// ② 双向通：节点回 Ack，判成功，结果类型为 Ack。
func TestPunchAcceptsPeerAck(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	meta := testMetadata()
	client, clientAddr := mustUDP(t)
	defer client.Close()
	peer, peerAddr := mustUDP(t)
	defer peer.Close()
	fakePeer(t, ctx, peer, clientAddr, meta, true)

	result, err := Punch(ctx, client, []netip.AddrPort{peerAddr}, meta)
	if err != nil {
		t.Fatalf("双向通却判失败: %v", err)
	}
	if result.Type != PunchAck || result.PeerAddr != peerAddr {
		t.Fatalf("结果不对: %+v", result)
	}
}

// ③ 节点侧 NAT 改写了端口：会合面下发的候选地址上没人，节点从另一个端口发 Hello。
// 客户端必须把 Hello 的来源加入候选，向它发 Hello 拿到 Ack。
func TestPunchLearnsPeerSourceAddress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	meta := testMetadata()
	client, clientAddr := mustUDP(t)
	defer client.Close()
	peer, peerAddr := mustUDP(t)
	defer peer.Close()
	dead, deadAddr := mustUDP(t)
	_ = dead.Close()
	fakePeer(t, ctx, peer, clientAddr, meta, true)

	result, err := Punch(ctx, client, []netip.AddrPort{deadAddr}, meta)
	if err != nil {
		t.Fatalf("节点端口被改写时判失败: %v", err)
	}
	if result.PeerAddr != peerAddr {
		t.Fatalf("对端地址 %v，期望 %v", result.PeerAddr, peerAddr)
	}
}

// ④ 与真实节点侧 ServerPuncher（非 direct 模式，双方都主动发 Hello）对打：两侧都判成功。
func TestPunchAgainstServerPuncher(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	meta := testMetadata()
	puncher, serverAddr := newServer(t, ctx)
	client, clientAddr := mustUDP(t)
	defer client.Close()

	serverErr := make(chan error, 1)
	go func() {
		_, err := puncher.Respond(ctx, "attempt-client-confirm", []netip.AddrPort{clientAddr}, meta, false)
		serverErr <- err
	}()
	// 生产中会合面事件先到节点、节点登记尝试后才开始打洞；这里同样等节点先登记。
	time.Sleep(50 * time.Millisecond)

	result, err := Punch(ctx, client, []netip.AddrPort{serverAddr}, meta)
	if err != nil {
		t.Fatalf("客户端判失败: %v", err)
	}
	if result.Type != PunchAck {
		t.Fatalf("客户端成功依据应为 Ack，实际 %d", result.Type)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("节点判失败: %v", err)
	}
}
