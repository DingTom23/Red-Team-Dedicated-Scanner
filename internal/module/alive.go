// 探活模块

package module

import (
	"math/rand"
	"net"
	"strconv"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/DingTom23/Red-Team-Dedicated-Scanner/internal/config"
	"github.com/DingTom23/Red-Team-Dedicated-Scanner/internal/engine"
	"github.com/DingTom23/Red-Team-Dedicated-Scanner/internal/priv"
)

type AliveModule struct {
	config.ScanConfig // 嵌入 ScanConfig 结构体，继承其字段
}

func (a AliveModule) Name() string {
	return "alive"
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

// tcpPing 函数用于一般用户使用的 TCP 端口探活
func tcpPing(target string, timeout time.Duration) bool {

	ports := config.DefaultPortsforAliveScan
	for _, port := range ports {
		address := net.JoinHostPort(target, strconv.Itoa(port))
		conn, err := net.DialTimeout("tcp", address, timeout)
		if err == nil {
			conn.Close()
			return true // 连接成功，目标主机存活
		}
	}

	return false // 所有端口连接失败，目标主机可能不存活
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
		Code: 0, // 代码为 0
		Body: &icmp.Echo{ // ICMP Echo 消息体
			ID: id,
			Seq: seq,
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

func (a AliveModule) Run(targets []string) ([]config.Result, error) {
	
	e := engine.NewEngine(a.ScanConfig)
	
	// 检查是否具有原始套接字权限
	hasrawPriv := priv.HasRawSocket()

	// 根据权限选择探测方法，如果有原始套接字权限，使用 ICMP 探测，否则使用 TCP 探测
	probe := func (ip string, port int) *config.Result {
		
		if hasrawPriv {
			icmpPing(ip, a.Timeout)
			return &config.Result{
				Target: ip,
				Detail: "Host is Alive (ICMP).",
			}
		} else {
			tcpPing(ip, a.Timeout)
			return &config.Result{
				Target: ip,
				Detail: "Host is Alive (TCP).",
			}
		}

		return nil
	}
	
	return e.Run(probe, targets, nil)
	
}


