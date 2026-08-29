package realm

// probe_errcode_test.go —— 归类一致性回归。
//
// 🔴 本文件守的是本轮的立身之本：**同一种失败，六协议必须归成同一个 error_code**。
// 2026-07-30 T5 实测发现原版只认 hy2 的 404 措辞，五协议的 404 被归成 unknown ——
// 面板上会显示成两类问题，而实际是一类（节点没分配给这个账号）。

import (
	"testing"

	squic "github.com/sagernet/sing-quic/hysteria2/realm"
	E "github.com/sagernet/sing/common/exceptions"
)

// TestClassify404IsSameCodeAcrossBothPaths 是「一把尺子」的直接断言：
// hy2 路径与五协议路径对同一个 404，必须给出同一个 error_code。
func TestClassify404IsSameCodeAcrossBothPaths(t *testing.T) {
	// hy2 路径：squic/hysteria2/client.go:510 的措辞。
	hy2Err := E.New("authentication failed, status code: 404")
	// 五协议路径：会合面控制客户端返回的结构化错误（control.go StatusError）。
	fiveErr := E.Cause(&squic.StatusError{
		StatusCode: 404,
		ErrorCode:  "realm_not_found",
		Message:    "realm not registered",
	}, "connect")

	hy2Code := classifyError(hy2Err)
	fiveCode := classifyError(fiveErr)

	if hy2Code != ErrCodeNotAssigned {
		t.Errorf("hy2 404 归类 = %q, want %q", hy2Code, ErrCodeNotAssigned)
	}
	if fiveCode != ErrCodeNotAssigned {
		t.Errorf("五协议 404 归类 = %q, want %q（原文：%s）", fiveCode, ErrCodeNotAssigned, fiveErr)
	}
	if hy2Code != fiveCode {
		t.Errorf("🔴 同一种失败归成了两个 code：hy2=%q 五协议=%q —— 这就是两把尺子",
			hy2Code, fiveCode)
	}
}

// TestClassifyStatusErrorByType 验证类型判断优先于措辞匹配。
func TestClassifyStatusErrorByType(t *testing.T) {
	cases := []struct {
		status int
		want   string
	}{
		{404, ErrCodeNotAssigned},
		{401, ErrCodeAuthFailure},
		{403, ErrCodeAuthFailure},
		{500, ErrCodeHTTPStatus},
		{502, ErrCodeHTTPStatus},
	}
	for _, tc := range cases {
		err := E.Cause(&squic.StatusError{StatusCode: tc.status, ErrorCode: "x"}, "connect")
		if got := classifyError(err); got != tc.want {
			t.Errorf("StatusCode=%d 归类 = %q, want %q", tc.status, got, tc.want)
		}
	}
}

// TestClassifyFlattenedControlWording 兜底路径：错误被扁平化成纯字符串后仍能归对。
func TestClassifyFlattenedControlWording(t *testing.T) {
	err := E.New("connect: control 404/realm_not_found: realm not registered")
	if got := classifyError(err); got != ErrCodeNotAssigned {
		t.Errorf("扁平化后的会合面 404 归类 = %q, want %q", got, ErrCodeNotAssigned)
	}
}
