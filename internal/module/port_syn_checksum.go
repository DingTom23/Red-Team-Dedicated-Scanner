package module

func checksum(data []byte) uint16 {
	sum := uint32(0)
	// 以 16 位（2 字节）为单位累加
	// 邻两个字节拼成一个 大端序 的 16 位无符号整数
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i]) << 8 | uint32(data[i+1])
	}
	
	// 奇数字节末尾处理
	// 若数据总长度为奇数，最后单独一个字节会被当作 高 8 位，低 8 位补 0，形成 16 位字
	if len(data) % 2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}

	// 进位折叠
	// 二进制反码加法的关键：若累加结果超出 16 位，高 16 位的进位要加到低 16 位上，循环直到高 16 位为 0
	for sum >> 16 >  0{
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	// 按位取反
	// ^uint16(sum) 对低 16 位做按位取反，得到最终的 16 位校验和。
	// 接收方在验证时，会对包含校验和的整个数据段再做相同的反码求和，正确结果应为 0xFFFF（全 1），否则说明出现比特错误
	return ^uint16(sum)
}


// TCP 的校验和并 不仅仅覆盖 TCP 报文，而是 伪首部 + TCP 报文。伪首部共 12 字节，结构为：
// 偏移	长度	内容
// 0	4	源 IP 地址
// 4	4	目的 IP 地址
// 8	1	全 0
// 9	1	协议号（TCP = 6）
// 10	2	TCP 段总长度（大端）
// 12	可变	TCP 头部 + 数据

func tcpChecksum(srcIP, dstIP [4]byte, tcpSegment []byte) uint16 {
	pseudo := make([]byte, 12+len(tcpSegment))
	copy(pseudo[0:4], srcIP[:])
	copy(pseudo[4:8], dstIP[:])
	// 在伪首部的设计里，偏移 8 和偏移 9 这两个字节是合在一起用的，组成一个 16 位（2 字节）的“协议”字段
	// 因为互联网校验和算法是以 16 位（2 字节）为单位 进行累加的，所以伪首部的每个字段都必须是 16 位的整数倍
	pseudo[8] = 0
	pseudo[9] = 6 // tcp
	pseudo[10] = byte(len(tcpSegment))
	pseudo[11] = byte(len(tcpSegment))
	copy(pseudo[12:], tcpSegment)
	return checksum(pseudo)
}

func ipChecksum(header []byte) uint16 {
	return checksum(header)
}