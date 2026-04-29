//go:build linux

package module

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"syscall"
	"time"
)

const (
	// 0x0800 表示后面的数据是 IPv4
	etherTypeIPv4 = 0x0800
	// 0x0806 表示后面的数据是 ARP
	etherTypeARP = 0x0806

	/*
	以太网帧里有一个 2 字节字段，用来说明 "我这个帧装的是什么协议"
	Ethernet Header
	目标 MAC | 源 MAC | EtherType | Payload
	如果 EtherType = 0x0806，网卡/系统就知道这是 ARP 包
	*/

	// 这是 ARP 报文里的"硬件类型"
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
	arpPayloadLen = 28
	// 这是整个 ARP 以太网帧长度：14 字节以太网头 + 28 字节 ARP 主体
	arpFrameLen = ethernetHeaderLen + arpPayloadLen
)

// htons 是 Host TO Network Short 的缩写，表示将主机字节序转换为网络字节序
// uint16 在内存里占 2 字节
// 小端 CPU（x86/x64/ARM）上（低地址存低字节）
// 网络协议要求大端（高地址存低字节）
func htons(v uint16) uint16 {

	// v      = 0x0806
	// v      = 00001000 00000110   (0x0806)
	// v<<8   = 00000110 00000000   (左移 8 位，低字节跑到高字节位置)
	// 0xFF00 = 11111111 00000000   (C 的整数提升规则在移位时可能把 uint16 提到 int，多出脏位。Go 没这个问题，移位结果类型不变。所以你可以不写 & 0xff00)
	// &      = 00000110 00000000   (只保留移位后的低字节)

	// v>>8   = 00000000 00001000   (右移 8 位，高字节跑到低字节位置)
	// 0x00FF = 00000000 11111111
	// &      = 00000000 00001000   (只保留移位后的高字节)
	// |      = 00000110 00001000   (位拼接)
	//        = 0x0608

	return (v<<8)&0xff00 | (v>>8)&0x00ff

}

// *net.Interface 指针，指向一张网卡结构体。如果找不到就返回 nil  net.Interface 是个 struct，比较大，返回指针避免拷贝整个结构体
// net.IP 本机在这张网卡上的 IPv4 地址
func findARPInterface(dstIP net.IP) (*net.Interface, net.IP, error) {

	// 拿网卡信息
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}

	
	for _, iface := range ifaces {
		
		// net.Interface 结构体
		//     type Interface struct {
		//     Index        int           // 网卡编号，比如 eth0 是 1
		//     MTU          int           // 最大传输单元
		//     Name         string        // 网卡名，比如 "eth0" "wlan0"
		//     HardwareAddr HardwareAddr  // MAC 地址
		//     Flags        Flags         // 标志位
		//     }

		// Flags 
		//     const (
		//     FlagUp           Flags = 1 << iota // 0x01 网卡已启用
		//     FlagBroadcast                      // 0x02 支持广播
		//     FlagLoopback                       // 0x04 是回环网卡
		//     FlagPointToPoint                   // 0x08 点对点连接（如 VPN）
		//     FlagMulticast                      // 0x10 支持多播
		// )

		// iface.Flags = 0x13
		// 这个数字里，每一个 bit 代表一个属性，多个属性叠加在一起。
		
		// iface.Flags = 00010011
		// net.FlagUp  = 00000001
		// &           = 00000001  ← 不是 0，说明 FlagUp 这一位是 1

		// iface.Flags = 00010010
		// net.FlagUp  = 00000001
		// &           = 00000000  ← 是 0，说明 FlagUp 这一位是 0

		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		// FlagLoopback = 0x04   // 是回环网卡（127.0.0.1）
		// 判断这个网卡是不是回环网卡
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		// MAC 地址不能为空
		if len(iface.HardwareAddr) == 0 {
			continue
		}

		// 拿到这张网卡的所有 IP 地址
		adds, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range adds {

			// 
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}



		}
	}


}

func arpPing(target string, timeout time.Duration) bool {

	



}