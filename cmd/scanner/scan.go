/*
先把命令骨架和 flags 写出来
在 Run() 里先接 AliveModule
提取 aliveTargets
再接 PortModule
先用最朴素的 fmt.Printf 打两段
*/

package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/DingTom23/Red-Team-Dedicated-Scanner/internal/module"
	"github.com/DingTom23/Red-Team-Dedicated-Scanner/internal/config"
	"github.com/DingTom23/Red-Team-Dedicated-Scanner/internal/parse"
)

func init() {

	var portStr string
	
	scanCmd := &cobra.Command{
		
		Use:   "scan",
		Short: "Chained host and port scan",

		Run: func (cmd *cobra.Command, args []string) {
			
			cfg := config.ScanConfig{ 
				
				Concurrency: concurrency,
				Timeout:     timeout,
				RateLimit:   rateLimit,
				Burst:       burst,
				Jitter:      jitter,

			}

			// 先运行 AliveModule 探活
			aliveModule := module.AliveModule{ScanConfig: cfg}
			aliveResults, err := aliveModule.Run([]string{target})
			if err != nil {
				exitError(err)
			}

			// 如果没有存活主机，直接输出结果并返回
			if len(aliveResults) == 0 {
				fmt.Println("No alive hosts found.")
				return
			}

			// 从 aliveResults 中提取 aliveTargets
			var aliveTargets []string
			for _, result := range aliveResults {
				aliveTargets = append(aliveTargets, result.Target)
			}

			// 运行 PortModule 端口扫描
			portModule := module.PortModule{ScanConfig: cfg}
			if portStr != "" {
				// 如果指定了端口范围，解析端口
				ports, err := parse.ParsePorts(portStr)
				if err != nil {
					exitError(err)
				}
				// 设置 PortModule 的端口列表
				portModule.Ports = ports
			}

			// 运行 PortModule 端口扫描
			portResults, err := portModule.Run(aliveTargets)
			if err != nil {
				exitError(err)
			}

			// 输出存活主机和开放端口的结果
			for _, result := range aliveResults {
                fmt.Printf("[scan][%s] %s - %s(%s/%s)\n", 
				aliveModule.Name(),
                result.Target,
                result.Detail,
                result.Method,
                result.Reason,
            )
            }

			for _, result := range portResults {
                fmt.Printf("[scan][%s] %s:%d - %s(%s/%s)\n", 
				portModule.Name(),
                result.Target,
                result.Port,
                result.Detail,
                result.Method,
                result.Reason,
            	)
            }
			

		},
	}


	scanCmd.Flags().StringVarP(&target, "target", "t", "", "Target IP or CIDR")
	scanCmd.MarkFlagRequired("target")
	scanCmd.Flags().StringVarP(&portStr, "ports", "p", "", "Port list (e.g. 80,443,8080-8090)")
	scanCmd.Flags().IntVarP(&concurrency, "concurrency", "c", 50, "Number of concurrent probes")
	scanCmd.Flags().DurationVarP(&timeout, "timeout", "T", 3*time.Second, "Probe timeout duration")
	scanCmd.Flags().IntVarP(&rateLimit, "rate", "r", 100, "Rate limit (Packets per second)")
	scanCmd.Flags().IntVarP(&burst, "burst", "b", 10, "Burst limit")
	scanCmd.Flags().Float64VarP(&jitter, "jitter", "j", 0.5, "Jitter factor (0.0 - 1.0)")

	rootCmd.AddCommand(scanCmd)

}

