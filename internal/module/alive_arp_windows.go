//go:build windows

package module

import (
	"encoding/binary"
	"net"
	"syscall"
	"time"
	"unsafe"
) 

var (
	// 加载 Windows 的 iphlpapi.dll
	// iphlpapi.dll 里有一些和 IP/网络辅助功能相关的系统函数
	// SendARP 就在这个 DLL 里
	iphlpapi = syscall.NewLazyDLL("iphlpapi.dll")
	// 从刚才加载的 iphlpapi.dll 里找到名叫 SendARP 的函数
	// 后面通过 procSendARP.Call(...) 调用它。
	procSendARP = iphlpapi.NewProc("SendARP")
)

func arpPing(target string, timeout time.Duration) bool {
	
	_ = timeout // 目前这个函数还没有实现超时功能，先占位

	// 192.168.1.10 -> [192, 168, 1, 10]
	ip := net.ParseIP(target).To4()
	if ip == nil {
		return false // 不是有效的 IPv4 地址
	}

	// 按“小端序”转换成一个 uint32 整数
	// [192, 168, 1, 10]  -> 167880896
	dstIP := binary.LittleEndian.Uint32(ip)

	// 声明一个长度固定为 6 的字节数组，用来接收 MAC 地址
	// AA:BB:CC:DD:EE:FF 就是 6 个字节
	var mac [6]byte
	macLen := uint32(len(mac))

	ret, _, _ := procSendARP.Call(
		uintptr(dstIP), // 目标 IP 地址
		0, // srcIP 设置为 0，表示让系统自动选择发送接口
		uintptr(unsafe.Pointer(&mac[0])), // 接收 MAC 地址的缓冲区
		uintptr(unsafe.Pointer(&macLen)), // 接收 MAC 地址长度的缓冲区
	)
	
	return ret == 0  && macLen > 0// 如果返回值为 0，说明调用成功，目标主机在线

}