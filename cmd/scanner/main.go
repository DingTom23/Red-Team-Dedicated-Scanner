package main

import (
	"fmt"
	"os"
	"time"

	"github.com/DingTom23/Red-Team-Dedicated-Scanner/internal/module"
	"github.com/spf13/cobra"
)

func main() {

	// Root Command / go 没有继承，只有组合 
	rootCmd := &cobra.Command{
		Use:	"scanner",
		Short:	"Internal network detector",
	}


	var target string

	var concurrency int
	var timeout time.Duration
	var rateLimit int
	var burst int
	var jitter float64
	
	// Sub Command / 探活
	aliveCmd := &cobra.Command{								
		Use:	"alive",
		Short:	"Host alive detection",
		Run:	func (cmd *cobra.Command, args []string) { 
			
			config := module.ScanConfig{
				Concurrency: concurrency,
				Timeout:     timeout,
				RateLimit:   rateLimit,
				Burst:       burst,
				Jitter:      jitter,
			} // 创建 AliveModule 实例

			m := module.AliveModule{
				ScanConfig: config,
			}
			
			results, err := m.Run([]string{target}) // 运行模块，传入目标地址
			
			// 检查是否有错误发生
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error occurred: %v\n", err)
				os.Exit(1)
			}
			
			// 如果没有找到存活的主机，输出提示信息
			if len(results) == 0 {
				fmt.Println("No alive hosts found.")
				return
			}


			// 输出结果，格式为 [模块名称] 目标地址 - 详细信息
			for _, result := range results {

				// %s 是字符串格式化占位符，用于插入字符串
				fmt.Printf("[%s] %s - %s\n", m.Name(), result.Target, result.Detail)
			}
		},
	}

	// 第1个 &target 把解析结果写入 target 变量（传指针）
	// 第2个 "target" 完整参数名，用 --target
	// 第3个 "t" 短参数名，用 -t
	// 第4个 "" 默认值，这里没有默认值，所以是空字符串
	// 第5个 帮助信息
	aliveCmd.Flags().
	StringVarP(&target, "target", "t", "", "Target IP or CIDR (e.g. 192.168.1.0/24)")
	
	// 将 "target" 标记为必需的参数
	aliveCmd.MarkFlagRequired("target")

	// 添加并发数量参数
	aliveCmd.Flags().
	IntVarP(&concurrency, "concurrency", "c", 50, "Number of concurrent probes")

	// 添加超时时间参数
	aliveCmd.Flags().
	DurationVarP(&timeout, "timeout", "T", 5 * time.Second, "Probe timeout duration")

	// 添加速率限制参数
	aliveCmd.Flags().
	IntVarP(&rateLimit, "rate", "r", 100, "Rate limit (Packets per second)")

	// 添加速率限制的突发值参数
	aliveCmd.Flags().
	IntVarP(&burst, "burst", "b", 10, "Burst limit (Packets per second)")

	// 添加时钟抖动参数
	aliveCmd.Flags().
	Float64VarP(&jitter, "jitter", "j", 0.5, "Jitter factor (0.0 - 1.0)")

	// 将 aliveCmd 添加到 rootCmd 中，使其成为一个子命令
	rootCmd.AddCommand(aliveCmd)

	// 条件判断 "如果 err 不为 nil，即发生了错误"
	if err := rootCmd.Execute(); err != nil {
		// 不会被 > 重定向，始终显示在终端
		fmt.Fprint(os.Stderr, err)
		os.Exit(1)
	}

}
