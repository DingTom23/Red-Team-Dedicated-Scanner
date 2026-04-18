package main

import (
    "fmt"
	"time"

    "github.com/DingTom23/Red-Team-Dedicated-Scanner/internal/config"
    "github.com/DingTom23/Red-Team-Dedicated-Scanner/internal/module"
    "github.com/spf13/cobra"
)

func init() {
    aliveCmd := &cobra.Command{
        Use:   "alive",
        Short: "Host alive detection",
        Run: func(cmd *cobra.Command, args []string) {
            cfg := config.ScanConfig{
                Concurrency: concurrency,
                Timeout:     timeout,
                RateLimit:   rateLimit,
                Burst:       burst,
                Jitter:      jitter,
            }

            m := module.AliveModule{ScanConfig: cfg}
            results, err := m.Run([]string{target})
            if err != nil {
                exitError(err)
            }

            if len(results) == 0 {
                fmt.Println("No alive hosts found.")
                return
            }

            for _, result := range results {
                fmt.Printf("[%s] %s - %s\n", m.Name(), result.Target, result.Detail)
            }
        },
    }

	// 第1个 &target 把解析结果写入 target 变量（传指针）
	// 第2个 "target" 完整参数名，用 --target
	// 第3个 "t" 短参数名，用 -t
	// 第4个 "" 默认值，这里没有默认值，所以是空字符串
	// 第5个 帮助信息

	// 目标 IP 或 CIDR 范围
    aliveCmd.Flags().StringVarP(&target, "target", "t", "", "Target IP or CIDR")

	// 将 "target" 标记为必需的参数
    aliveCmd.MarkFlagRequired("target")
    
	// 添加并发数量参数
	aliveCmd.Flags().IntVarP(&concurrency, "concurrency", "c", 50, "Number of concurrent probes")
    
	// 添加超时时间参数
	aliveCmd.Flags().DurationVarP(&timeout, "timeout", "T", 5 * time.Second, "Probe timeout duration")
    
	// 添加速率限制参数
	aliveCmd.Flags().IntVarP(&rateLimit, "rate", "r", 100, "Rate limit (Packets per second)")

	// 添加突发限制参数
	aliveCmd.Flags().IntVarP(&burst, "burst", "b", 10, "Burst limit")

	// 添加抖动参数	
	aliveCmd.Flags().Float64VarP(&jitter, "jitter", "j", 0.5, "Jitter factor (0.0 - 1.0)")

	// 将 aliveCmd 添加到根命令
    rootCmd.AddCommand(aliveCmd)
}