//go:build linux

package module

import (
	"net"
	"time"

)

const (
	// 0x0800 表示后面的数据是 IPv4
	etherTypeIPv4 = 0x0800
	// 0x0806 表示后面的数据是 ARP
	etherTypeARP  = 0x0806

	/*
	以太网帧里有一个 2 字节字段，用来说明 “我这个帧装的是什么协议”
	Ethernet Header
	目标 MAC | 源 MAC | EtherType | Payload
	如果 EtherType = 0x0806，网卡/系统就知道这是 ARP 包
	*/

	// 这是 ARP 报文里的“硬件类型”
	// 0x0001 表示以太网 Ethernet
	// ARP 不一定只能跑在以太网上，所以它需要一个字段说明当前硬件网络类型
	// 现在常见局域网基本都是以太网，所以这里写 0x0001 
	arpHardwareEthernet = 0x0001

	// 这是 ARP 报文里的操作类型
	// 0x0001 表示 ARP Request 请求
	// 0x0002 表示 ARP Reply 响应
	arpOperationRequest = 0x0001
	arpOperationReply   = 0x0002

	// 这是以太网头长度，固定 14 字节
	ethernetHeaderLen = 14
	// 这是 ARP 报文主体长度，在 Ethernet + IPv4 场景下固定 28 字节
	arpPayloadLen     = 28
	// 这是整个 ARP 以太网帧长度：14 字节以太网头 + 28 字节 ARP 主体
	arpFrameLen       = ethernetHeaderLen + arpPayloadLen
)

func arpPing(target string, timeout time.Duration) bool {

	if timeout <= 0 {
		timeout = 2 * time.Second // 默认超时时间 2 秒
	}

	dstIP := net.ParseIP(target).To4()
	if dstIP == nil {
		return false // 解析 IP 失败，直接返回 false
	}

	iface, srcIP, err := findARPInterface()
}

// *net.Interface？因为函数要返回找到的那张网卡，如果没找到就返回 nil
/*
	iface = WLAN 网卡
	srcIP = 192.168.1.5
	err = nil
*/
func findARPInterface(dstIP net.IP) (*net.Interface, net.IP, error) {
	
	// 获取本机所有网络接口，比如 WLAN、以太网、虚拟网卡等
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}

	// 
	for _, i := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // 网卡没启用，跳过
		}
	}




} 