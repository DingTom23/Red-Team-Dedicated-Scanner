package module

import (
	"sync"
	"time"
	"net"
	"strconv"
	"math/rand"


	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"github.com/DingTom23/Red-Team-Dedicated-Scanner/internal/config"
	

)

type AliveProber interface {

	Probe(target string, timeout time.Duration) *config.Result
	Name() string

}

// ICMPProber 表示使用 ICMP Echo 的存活探针。
// 当前结构体没有字段，因为它暂时不需要保存额外状态。
type ICMPProber struct {}


// TCPProber 表示使用 TCP Connect 的存活探针。
// Ports 表示用于探活的端口列表，只要任意一个端口能证明目标在线，就认为主机存活。
type TCPProber struct {
	
	Ports []int

}

func (p ICMPProber) Name() string {

	return "icmp"

}


func (p ICMPProber) Probe(target string, timeout time.Duration) *config.Result {

	if icmpPing(target, timeout) {
		return &config.Result{
			Target: target,
			Detail: "Host is alive (ICMP).",
			Method: "icmp",
			Reason: "echo-reply",
		}
	}

	return nil
}

// makeRandomBytes 生成一个随机字节切片，长度为 n，用于生成随机数据
func makeRandomBytes(n int) []byte {

	// 创建一个长度为 n 的字节切片
	b := make([]byte, n)

	// 填充随机字节
	rand.Read(b)

	// 返回随机字节切片
	return b
}

// icmpPing 函数用于发送 ICMP Echo 请求并等待回复，判断目标主机是否存活
func icmpPing(target string, timeout time.Duration) bool {

	// 监听 ipv4 的 ICMP 协议，绑定到本地地址 "0.0.0.0"
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")

	if err != nil {
		return false
	}

	defer conn.Close() // 推迟到函数结束时执行

	// 将目标地址解析为 IP 地址
	dst, err := net.ResolveIPAddr("ip4", target)

	if err != nil {
		return false
	}

	id := rand.Intn(65535)
	seq := rand.Intn(65535)

	// 构造 ICMP Echo 请求消息
	msg := icmp.Message{

		Type: ipv4.ICMPTypeEcho, // ICMP Echo 请求
		Code: 0,                 // 代码为 0
		Body: &icmp.Echo{ // ICMP Echo 消息体
			ID:   id,
			Seq:  seq,
			Data: makeRandomBytes(56),
		},
	}

	data, err := msg.Marshal(nil) // 将消息序列化为字节切片 - 需要理解一下?

	if err != nil {
		return false
	}

	// 设置发送和接收的超时时间
	conn.SetDeadline(time.Now().Add(timeout))

	_, err = conn.WriteTo(data, dst) // 发送 ICMP Echo 请求

	if err != nil {
		return false
	}

	for {
		// 接收 ICMP 回复
		// 创建一个足够大的缓冲区来接收回复
		reply := make([]byte, 1500)

		// 读取回复数据
		n, _, err := conn.ReadFrom(reply)

		if err != nil {
			return false
		}

		// 解析 ICMP 回复消息
		replyMsg, err := icmp.ParseMessage(ipv4.ICMPTypeEcho.Protocol(), reply[:n])

		if err != nil {
			return false
		}

		// 如果回复消息的类型不是 ICMP Echo 回复，继续等待下一个回复
		if replyMsg.Type != ipv4.ICMPTypeEchoReply {
			continue
		}

		// 将消息体断言为 *icmp.Echo 类型，获取 Echo 回复的 ID 和序列号，确保它们与我们发送的请求匹配
		echoReply, ok := replyMsg.Body.(*icmp.Echo)

		// 如果断言失败，说明消息体不是我们期望的类型，继续等待下一个回复
		if !ok {
			continue
		}

		// 如果 ID 和序列号匹配，说明这是我们发送的 Echo 请求的回复，目标主机存活，返回 true
		if echoReply.ID == id && echoReply.Seq == seq {
			return true
		}

	}

}

// Name 返回 TCP 探针的名称
func (p TCPProber) Name() string {
	
	return "tcp" 

}

// tcpPing 函数用于一般用户使用的 TCP 端口探活
// func tcpPing(target string, timeout time.Duration) bool {

// 	ports := config.DefaultPortsforAliveScan
// 	results := make(chan bool, len(ports))

// 	var waitGroup sync.WaitGroup
// 	for _, port := range ports {
// 		waitGroup.Add(1)

// 		go func(port int) {
// 			defer waitGroup.Done()

// 			address := net.JoinHostPort(target, strconv.Itoa(port))
// 			conn, err := net.DialTimeout("tcp", address, timeout)
// 			if err == nil {
// 				conn.Close()
// 				results <- true
// 				return
// 			}

// 			results <- false
// 		}(port)
// 	}

// 	go func() {
// 		waitGroup.Wait()
// 		close(results)
// 	}()

// 	for ok := range results {
// 		if ok {
// 			return true // 任意一个端口连接成功，目标主机存活
// 		}
// 	}

// 	return false // 所有端口连接失败，目标主机可能不存活
// }


// ping 函数用于进行 TCP 端口探活 代替老的 tcpPing 函数，支持多个端口的并发探测
func (p TCPProber) ping(ip string, timeout time.Duration) bool {

	// 创建一个 bool 类型的带缓冲 channel
	results := make(chan bool, len(p.Ports))

	// 启动多个 goroutine 并发探测每个端口
	var wg sync.WaitGroup

	// 遍历端口列表，为每个端口启动一个 goroutine 进行探测
	for _, port := range p.Ports {

		wg.Add(1)

		go func(port int) {
			
			defer wg.Done()

			// 拼接 IP 地址和端口号，形成完整的 TCP 地址
			address := net.JoinHostPort(ip, strconv.Itoa(port))
			conn, err := net.DialTimeout("tcp", address, timeout)
			
			// 如果连接成功，关闭连接，将 true 写入 channel
			if err == nil {
				conn.Close()
				results <- true
				return
			}

			results <- false
		
		}(port)
	}


	// 等待所有 goroutine 完成，关闭 channel
	go func() {
		// 等待所有 goroutine 完成
		wg.Wait()
		// 所有 goroutine 完成后，关闭 channel
		close(results)
	}()

	// 遍历 channel 中的结果，如果有任意一个端口连接成功，返回 true -> 因为是探活
	// 如果所有端口都连接失败，返回 false
	for ok := range results {
		if ok {
			return true // 任意一个端口连接成功，目标主机存活
		}
	}

	return false

}

// Probe 方法用于进行 TCP 端口探活
func (p TCPProber) Probe(ip string, timeout time.Duration) *config.Result {

	if p.ping(ip, timeout) {
		return &config.Result{
			Target: ip,
			Detail: "Host is alive (TCP).",
			Method: "tcp",
			Reason: "tcp-connect",
		}
	}

	return nil

}