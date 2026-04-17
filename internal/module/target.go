// CIDR 解析

package module

import (
	"fmt"
	"net"
	"strings"
)


func incIP(ip net.IP) {

	// 最后一个字节的索引 (IPv4 是 3)
	for j := len(ip) - 1; j >= 0; j-- {

		// IP 地址底层就是一个字节数组，每个字节范围 0~255
		// 192.168.1.0  ->  [192, 168, 1, 0]
		// 索引:        -> 	[0] [1] [2] [3]

		// 从最后一个字节开始递增，如果超过 255 就进位到前一个字节
		
		// net.IP 的底层类型
		// net.IP 底层是 []byte，而 byte 就是 uint8——无符号 8 位整数
		// 所以到 255 就会回到 0，继续递增前一个字节
		ip[j]++
		
		// 如果是 0 了，还需要继续递增前一个字节
		if ip[j] > 0 {
			break
		}
	}
}


// 传入一个 CIDR 字符串，返回一个包含所有 IP 地址的字符串切片
func ParseTargets(target []string) ([]string, error) {

	// IP addresses
	var ips []string

	for _, t := range target {

		// 判断字符串中是否包含 "/"，如果包含，说明是 CIDR 格式
		if strings.Contains(t, "/") {

			// 解析 CIDR 字符串，得到 IP 网络对象
			ip, ipnet, err := net.ParseCIDR(t)

			// eg. 输入: "192.168.1.100/24"
			// ip         = 192.168.1.100   <- 你输入的那个 IP
			// ipnet.IP   = 192.168.1.0     <- 网络地址（掩码计算后的起始地址）

			// ip net.IP 输入的 IP 地址	192.168.1.100
			// ipnet *net.IPNet	网络信息（含掩码和范围） 192.168.1.0/24

			// ipnet.IP	192.168.1.0	网络起始地址
			// ipnet.Mask ffffff00（即 255.255.255.0） 子网掩码



			if err != nil {
				return nil, err
			}

			// 遍历 CIDR 范围内的所有 IP 地址
			// Contains 控制：还在网段内就继续循环
			for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
				ips = append(ips, ip.String())
			}

		}else { // 如果不包含 "/"，说明是单个 IP 地址
			
			// 解析出来 ip 地址
			ip := net.ParseIP(t)
			
			// 如果输入的字符串不是有效的 IP 地址，ParseIP 会返回 nil
			if ip == nil {
				return nil, fmt.Errorf("invalid IP address: %s", t)
			}

			// 直接添加到结果切片
			ips = append(ips, t)
		}
	}
	return ips, nil
}