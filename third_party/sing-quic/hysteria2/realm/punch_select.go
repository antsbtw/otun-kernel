package realm

import "time"

// DefaultV6PreferGrace:v4 先打通后,再等 v6 这么久;v6 在窗口内打通就改用 v6。
//
// 依据(2026-10-15 中国移动 iPhone 真机,CLIENT_ISSUE_2026-10-14 / BACKEND_REPLY_2026-10-14 §3.2):
// 同一手机、同一节点,v4 打洞能成功但数据面不可用(僵尸连接 7 分钟),换 v6 立即恢复;
// 新加坡同类现象(打洞小包能过、QUIC 大包被丢)也只出现在 v4。打洞成功只证明小包能过,
// 不证明数据能走 —— 两族都能打通时 v6 更可靠。
//
// 取 300ms:节点开局同时往两族候选发 hello,客户端两族收包只差路径时延差(几十 ms),
// v6 能通时几乎都落在窗口内;v6 不通时只多等 300ms。
const DefaultV6PreferGrace = 300 * time.Millisecond

// PunchOutcome 是一路地址族打洞的结果。F 为调用方的地址族 socket 类型
// (hy2 client.go 的 realmFamilyConn / kernel transport/realm 的 familyConn)。
type PunchOutcome[F any] struct {
	Family F
	IPv4   bool
	Result PunchResult
	Err    error
}

// SelectPunchWinner 从各地址族的打洞结果里选胜者,两份竞速实现共用:
//   - v6 先打通:直接用 v6;
//   - v4 先打通:若 v6 还在打,再等最多 v6Grace;v6 在窗口内打通就用 v6,否则用 v4;
//   - v6Grace <= 0:退化为原来的"谁先打通用谁"。
//
// pending 是 out 里尚未读出的结果数(= 参赛地址族数)。返回 ok=false 表示全部失败,
// failures 按到达顺序收集所有失败结果(调用方据此拼错误、关 socket)。
func SelectPunchWinner[F any](out <-chan PunchOutcome[F], pending int, v6Grace time.Duration) (winner PunchOutcome[F], ok bool, failures []PunchOutcome[F]) {
	var v4Win *PunchOutcome[F]
	var grace <-chan time.Time
	received := 0
	for received < pending {
		select {
		case o := <-out:
			received++
			if o.Err != nil {
				failures = append(failures, o)
				if !o.IPv4 && v4Win != nil {
					// 在等的 v6 失败了 → 用 v4(参赛最多 v4/v6 各一路,v4 胜出后剩下的就是 v6)
					return *v4Win, true, failures
				}
				continue
			}
			if !o.IPv4 {
				return o, true, failures
			}
			// v4 打通
			if v6Grace <= 0 || received >= pending {
				return o, true, failures
			}
			v4Win = &o
			grace = time.After(v6Grace)
		case <-grace:
			return *v4Win, true, failures
		}
	}
	if v4Win != nil {
		return *v4Win, true, failures
	}
	return PunchOutcome[F]{}, false, failures
}
