package realm

import (
	"errors"
	"testing"
	"time"
)

type fakeFamily string

func send(out chan PunchOutcome[fakeFamily], after time.Duration, family string, err error) {
	go func() {
		time.Sleep(after)
		out <- PunchOutcome[fakeFamily]{Family: fakeFamily(family), IPv4: family == "v4", Err: err}
	}()
}

func TestSelectPunchWinner(t *testing.T) {
	fail := errors.New("punch timeout")
	cases := []struct {
		name       string
		v4At, v6At time.Duration
		v4Err      error
		v6Err      error
		grace      time.Duration
		want       string // "" = 全失败
		maxElapsed time.Duration
	}{
		{"v6 先通直接用", 50 * time.Millisecond, 10 * time.Millisecond, nil, nil, 300 * time.Millisecond, "v6", 40 * time.Millisecond},
		{"v4 先通、v6 窗口内通 → 用 v6", 10 * time.Millisecond, 80 * time.Millisecond, nil, nil, 300 * time.Millisecond, "v6", 150 * time.Millisecond},
		{"v4 先通、v6 失败 → 立即用 v4", 10 * time.Millisecond, 40 * time.Millisecond, nil, fail, 300 * time.Millisecond, "v4", 100 * time.Millisecond},
		{"v4 先通、v6 太慢 → 窗口到点用 v4", 10 * time.Millisecond, 2 * time.Second, nil, nil, 300 * time.Millisecond, "v4", 450 * time.Millisecond},
		{"v6 先失败、v4 后通 → 不等直接用 v4", 80 * time.Millisecond, 10 * time.Millisecond, nil, fail, 300 * time.Millisecond, "v4", 150 * time.Millisecond},
		{"grace=0 退化为谁先通用谁", 10 * time.Millisecond, 80 * time.Millisecond, nil, nil, 0, "v4", 50 * time.Millisecond},
		{"两族都失败", 10 * time.Millisecond, 20 * time.Millisecond, fail, fail, 300 * time.Millisecond, "", 100 * time.Millisecond},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := make(chan PunchOutcome[fakeFamily], 2)
			send(out, tc.v4At, "v4", tc.v4Err)
			send(out, tc.v6At, "v6", tc.v6Err)
			start := time.Now()
			winner, ok, failures := SelectPunchWinner(out, 2, tc.grace)
			elapsed := time.Since(start)
			got := ""
			if ok {
				got = string(winner.Family)
			}
			if got != tc.want {
				t.Fatalf("winner=%q want %q (failures=%d)", got, tc.want, len(failures))
			}
			if !ok && len(failures) != 2 {
				t.Fatalf("all-fail must report both failures, got %d", len(failures))
			}
			if elapsed > tc.maxElapsed {
				t.Fatalf("took %v, want <= %v", elapsed, tc.maxElapsed)
			}
		})
	}
}

// 只有一路地址族参赛(纯 v4 设备 / v6 在找地址时已退出):v4 打通立即返回,不等窗口。
func TestSelectPunchWinnerSingleFamilyNoWait(t *testing.T) {
	out := make(chan PunchOutcome[fakeFamily], 1)
	send(out, 10*time.Millisecond, "v4", nil)
	start := time.Now()
	winner, ok, _ := SelectPunchWinner(out, 1, 2*time.Second)
	if !ok || winner.Family != "v4" {
		t.Fatalf("want v4, got %v %v", ok, winner.Family)
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatalf("single family must not wait for grace")
	}
}
