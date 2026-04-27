package main

import (
    
    "fmt"
	"time"
    "encoding/json"

    "github.com/spf13/cobra"

    "github.com/DingTom23/Red-Team-Dedicated-Scanner/internal/config"
    "github.com/DingTom23/Red-Team-Dedicated-Scanner/internal/module"
    "github.com/DingTom23/Red-Team-Dedicated-Scanner/internal/parse"
    

)

func init() {
    
    // 定义 JSON 输出标志
    var jsonOutput bool

    // 定义扫描端口
    var portStr string

    portCmd := &cobra.Command{
        Use:   "port",
        Short: "Port scan",
        Run: func(cmd *cobra.Command, args []string) {
            cfg := config.ScanConfig{
                Concurrency: concurrency,
                Timeout:     timeout,
                RateLimit:   rateLimit,
                Burst:       burst,
                Jitter:      jitter,
            }

            m := module.PortModule{ScanConfig: cfg}

            if portStr != "" {
                ports, err := parse.ParsePorts(portStr)
                if err != nil {
                    exitError(err)
                }
                m.Ports = ports
            }

            results, err := m.Run([]string{target})
            if err != nil {
                exitError(err)
            }

            if len(results) == 0 {
                fmt.Println("No open ports found.")
                return
            }

            if jsonOutput {
                
                data, err := json.MarshalIndent(results, "", "  ")
                if err != nil {
                    exitError(err)
                }

                fmt.Println(string(data))
                return
            }

            for _, result := range results {
                fmt.Printf("[%s] %s:%d - %s\n", m.Name(), 
                result.Target, 
                result.Port, 
                result.Detail,
                )
            }
        },
    }

    portCmd.Flags().StringVarP(&portStr, "ports", "p", "", "Port list (e.g. 80,443,8080-8090)")
    portCmd.Flags().StringVarP(&target, "target", "t", "", "Target IP or CIDR")
    portCmd.MarkFlagRequired("target")
    portCmd.Flags().IntVarP(&concurrency, "concurrency", "c", 50, "Number of concurrent probes")
    portCmd.Flags().DurationVarP(&timeout, "timeout", "T", 3*time.Second, "Probe timeout duration")
    portCmd.Flags().IntVarP(&rateLimit, "rate", "r", 100, "Rate limit (Packets per second)")
    portCmd.Flags().IntVarP(&burst, "burst", "b", 10, "Burst limit")
    portCmd.Flags().Float64VarP(&jitter, "jitter", "j", 0.5, "Jitter factor (0.0 - 1.0)")
    portCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output results in JSON format")

    rootCmd.AddCommand(portCmd)
}