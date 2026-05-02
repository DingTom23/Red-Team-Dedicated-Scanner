package module

import (
	"encoding/binary"
	"math/rand"
	"net"
)

type SYNProber struct {
	SrcIP net.IP
	Ports []int
}

func (p SYNProber) Name() string {
	return "syn"
}

func buildSYNPacket(srcIP, dstIP net.IP, dstPort int) []byte {
	// 随机从 1024-61024 中选一个伪装成 源端口
	srcPort := uint16(rand.Intn(60000) + 1024)

	// IP 头 20 bytes
	ipHeader := make([]byte, 20)
	// IHL 字段的数值，不代表“字节数”，而代表“32 位字（4 字节）的个数”
	ipHeader[0] = 0x45 // Version=4(IPv4), IHL=5(IHL 的数值 × 4 = IP 头部的实际字节数   首部长度 = 5 × 4 = 20 字节)
	ipHeader[1] = 0x00 // Tos(Type of Service)

	// ID random
	binary.BigEndian.PutUint16(ipHeader[4:6], uint16(rand.Intn(65536)))
	// Flags=DF, Offset=0
	binary.BigEndian. PutUint16(ipHeader[6:8], 0x4000)

	copy(ipHeader[12:16], srcIP.To4())
	copy(ipHeader[16:20], dstIP.To4())

	tcpHeader := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHeader[0:2], srcPort)
	binary.BigEndian.PutUint16(tcpHeader[2:4], uint16())


}