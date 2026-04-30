//go:build linux

package module

import (
	"encoding/binary"
	"errors"
	"net"
	"time"
	"syscall"
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
		
		// net.Addr 接口类型的切片，里面可能装的是 *net.IPNet 也可能是 *net.IPAddr
		// 拿到这张网卡的所有 IP 地址
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {

			// MAC 地址不能为空
			if len(iface.HardwareAddr) == 0 {
				continue
			}

			// 这个地方返回的是 [adds {

			// 尝试将 addr 转换为 *net.IPNet 类型
			ipNet, ok := addr.(*net.IPNet)
			// 不是 *net.IPNet 类型就继续转下一个
			if !ok {
				continue
			}

			// 取出 ip 字段，转换成 IPv4 格式
			srcIP := ipNet.IP.To4()
			// 不是 IPv4 就继续转下一个
			if srcIP == nil {
				continue
			}

			// 找到一张“目标 IP 就在这张网卡网段里”的网卡，然后立刻返回它
			if ipNet.Contains(dstIP) {
				// 显式表达“我要返回一个独立副本的地址”
				// 在 Go 1.21 及更早，range 变量复用是经典坑
				// 如果把 &iface 存起来，后面可能多个地方都指向同一个循环变量
				ifaceCopy := iface
				return &ifaceCopy, srcIP, nil
			}
		}
	}

	return nil, nil, errors.New("no usable interface for ARP target")

}

func buildARPRequest(srcMAC net.HardwareAddr, srcIP, dstIP net.IP) []byte {

	// 开始构造 ARP 请求帧
	frame := make([]byte, arpFrameLen)

	// --- 以太网头 (0..13) ---

	// (0..13) 是说下面这段代码处理的是帧的第 0 字节到第 13 字节，共 14 字节，对应以太网头的全部三个字段：
	// 字节 0 ─ 5:   目标 MAC（6 字节）
	// 字节 6 ─ 11:  源 MAC（6 字节）
	// 字节 12 ─ 13: EtherType（2 字节）
	// 广播 ff:ff:ff:ff:ff:ff 是说目标 MAC 填全 F，代表二层广播。交换机看到这个地址，会把帧原样发给局域网里所有设备

	// 目标 MAC 广播 ff:ff:ff:ff:ff:ff:ff
	for i := 0; i < 6; i++ {
		frame[i] = 0xff
	}
	
	// 写入源 MAC
	copy(frame[6:12], srcMAC) 

	binary.BigEndian.PutUint16(frame[12:14], etherTypeARP)

	// Go 语言的切片共享底层数组
	arp := frame[ethernetHeaderLen:]

	// --- ARP 主体 (14..41) ---

	// (14..15) 硬件类型 Ethernet
	binary.BigEndian.PutUint16(arp[0:2], arpHardwareEthernet)

	// (16..17) 协议类型 IPv4
	binary.BigEndian.PutUint16(arp[2:4], etherTypeIPv4)

	// (18) 硬件地址长度 6
	arp[4] = 6
	
	// (19) 协议地址长度 4
	arp[5] = 4

	// (20..21) ARP 操作码 Request
	binary.BigEndian.PutUint16(arp[6:8], arpOperationRequest)

	// (8..13) 发送者 MAC 地址
	copy(arp[8:14], srcMAC)

	// (14..17) 发送者 IP 地址
	copy(arp[14:18], srcIP.To4())

	// (24..27) 目标 IP 地址
	copy(arp[24:28], dstIP.To4())
	
	return frame

}

func isARPReply(frame []byte, expectedSenderIP, localIP net.IP) bool {
	
	// 如果帧长度不足，不是 ARP 回复帧
	if len(frame) < arpFrameLen {
		return false
	}

	// etherTypeARP
	etherType := binary.BigEndian.Uint16(frame[12:14])
	if etherType != etherTypeARP {
		return false
	}

	arp := frame[ethernetHeaderLen:]

	// 检查 ARP 操作码是否是 Reply
	operation := binary.BigEndian.Uint16(arp[6:8])
	if operation != arpOperationReply {
		return false
	}

	// 检查发送者 IP 是否匹配
	senderIP := net.IP(arp[14:18])
	if !senderIP.Equal(expectedSenderIP) {
		return false
	}

	targetIP := net.IP(arp[24:28])
	if !targetIP.Equal(localIP) {
		return false
	}

	return true

}

func arpPing(target string, timeout time.Duration) bool {

	dstIP := net.ParseIP(target).To4()
	if dstIP == nil {
		return false
	}

	iface, srcIP, err := findARPInterface(dstIP)
	if err != nil {
		return false
	}

	if srcIP.Equal(dstIP){
		return true
	}
	
	// AF_INET    →  IP 层    →  只能发 IP 数据包（TCP/UDP/ICMP）
	// AF_PACKET  →  链路层   →  可以手搓完整的以太网帧
	// SOCK_RAW   →  自己的帧原样发出
	// SOCK_DGRAM →  内核帮忙做一些处理（但 AF_PACKET 下区别不大）
	// int(htons(etherTypeARP)) 这个地方过滤了一下
	// socket A: protocol = htons(0x0806)  →  只收到 ARP 帧
	// socket B: protocol = htons(0x0800)  →  只收到 IPv4 帧
	// socket C: protocol = htons(0x0000)  →  收到所有帧（不设防）
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(etherTypeARP)))
	if err != nil {
		return false
	}
	defer syscall.Close(fd)

	// 设置接收超时
    tv := syscall.Timeval{
        Sec:  int64(timeout / time.Second),
        Usec: int64(timeout % time.Second) / 1000,
    }
    if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
        return false
    }

    // 绑定到目标网卡
    sa := syscall.SockaddrLinklayer{
        Protocol: htons(etherTypeARP),
        Ifindex:  iface.Index,
        Halen:    6,
    }
    if err := syscall.Bind(fd, &sa); err != nil {
        return false
    }

    // 构造并发送 ARP 请求
    frame := buildARPRequest(iface.HardwareAddr, srcIP, dstIP)

    broadcastAddr := syscall.SockaddrLinklayer{
        Protocol: htons(etherTypeARP),
        Ifindex:  iface.Index,
        Halen:    6,
        Addr:     [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00},
    }

    if err := syscall.Sendto(fd, frame, 0, &broadcastAddr); err != nil {
        return false
    }

    // 循环接收 ARP Reply
    buf := make([]byte, 1500)
    for {
        n, _, err := syscall.Recvfrom(fd, buf, 0)
        if err != nil {
            return false
        }

        if isARPReply(buf[:n], dstIP, srcIP) {
            return true
        }
    }
}