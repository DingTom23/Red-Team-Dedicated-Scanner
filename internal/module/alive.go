// 探活模块

package module

import (

	"fmt"

	"github.com/DingTom23/Red-Team-Dedicated-Scanner/internal/config"
	"github.com/DingTom23/Red-Team-Dedicated-Scanner/internal/engine"
	"github.com/DingTom23/Red-Team-Dedicated-Scanner/internal/priv"

)

type AliveModule struct {

	// 嵌入 ScanConfig 结构体，继承其字段
	config.ScanConfig 

	// 探测方法
	ProbeMethod string 

}

func (a AliveModule) Name() string {
	return "alive"
}


func (a AliveModule) Run(targets []string) ([]config.Result, error) {

	e := engine.NewEngine(a.ScanConfig)

	var prober AliveProber

	// 检查是否具有原始套接字权限
	// 根据权限选择探测方法，如果有原始套接字权限，使用 ICMP 探测，否则使用 TCP 探测

	switch a.ProbeMethod {
		case "icmp":
			prober = ICMPProber{}
		case "tcp":
			prober = TCPProber{
				Ports: config.DefaultPortsforAliveScan, // 使用默认端口列表进行 TCP 探测
			}
		case "arp":
			prober = ARPProber{}
		// case "syn":
		// 	prober = SYNProber{}
		case "auto", "":
			if priv.HasRawSocket() {
				prober = ICMPProber{}
			} else {
				prober = TCPProber{
					Ports: config.DefaultPortsforAliveScan, // 使用默认端口列表进行 TCP 探测
				}
			}
		default:
			return nil, fmt.Errorf("unsupported alive probe method: %s", a.ProbeMethod)
	}

	probe := func (ip string, port int) *config.Result {
		return prober.Probe(ip, a.Timeout)
	}

	return e.Run(probe, targets, nil)

}


