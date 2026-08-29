// Command probe-cli 是探针入口(experimental/probeentry)的最简命令行驱动:
// 从 stdin 读一条 spec JSON(枚举 API 的 per_protocol + 探测控制字段),跑一次
// RunProbe,把结构化 Result 打到 stdout。binder=nil(Linux 上不绑定网络)。
//
// 用途:分层验证第 1 步 —— 在 Linux 上对真实节点跑通某条 {协议,路径},证明入口层
// 与内核链路,不依赖 aar/安卓/真机。典型:relay_only 验证中继链路本身闭环。
//
//	echo '<spec json>' | go run -tags with_utls ./cmd/probe-cli
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/sagernet/sing-box/experimental/probeentry"
)

func main() {
	fetch := flag.Bool("fetch", false, "读 FetchSpec(登录 portal 取全部节点连接串)并打印生成的 Spec 列表")
	flag.Parse()

	stdin, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read stdin:", err)
		os.Exit(2)
	}

	if *fetch {
		var fs probeentry.FetchSpec
		if err := json.Unmarshal(stdin, &fs); err != nil {
			fmt.Fprintln(os.Stderr, "parse fetch spec:", err)
			os.Exit(2)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 130*time.Second)
		defer cancel()
		res := probeentry.FetchTargets(ctx, &fs)
		out, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(out))
		if res.Err != "" {
			os.Exit(1)
		}
		return
	}

	var spec probeentry.Spec
	if err := json.Unmarshal(stdin, &spec); err != nil {
		fmt.Fprintln(os.Stderr, "parse spec:", err)
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	res := probeentry.RunProbe(ctx, &spec, nil)
	out, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(out))

	if !res.Success {
		os.Exit(1)
	}
}
