package module

import (
	
	"time"

	"github.com/DingTom23/Red-Team-Dedicated-Scanner/internal/config"

)

// 定义一个结构体，但这个结构体现在没有任何字段。它本身不保存状态，只是作为一种“探测方法”的载体。
type ARPProber struct {}

func (p ARPProber) Name() string {
	return "arp"
}

func (p ARPProber) Probe(target string, timeout time.Duration) *config.Result {

	if arpPing(target, timeout) {
		return &config.Result{
			Target: target,
			Method: p.Name(),
			Reason: "arp-reply",
			Detail: "Host is alive (ARP).",
		}
	}

	// 先做占位，后面再接真实 ARP 探测
	return nil

}