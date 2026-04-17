// 探活模块

package module

import (
	"context"
	"net"
	"sync"
	"time"
	"math/rand"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/time/rate"
)

type AliveModule struct {
	ScanConfig // 嵌入 ScanConfig 结构体，继承其字段
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


func (a AliveModule) Run(targets []string) ([]Result, error) {
	
	ips, err := ParseTargets(targets)

	if err != nil {
		return nil, err
	}

	var results []Result
	
	// goroutine   go 的轻量级线程，go func() 即可启动
	// channel   goroutine 之间传递数据的管道
	// sync.WaitGroup   等待一组 goroutine 完成 

	// 使用互斥锁和 WaitGroup 来处理并发访问 results 切片
	var mu sync.Mutex
	var wg sync.WaitGroup

	// 创建一个速率限制器，限制每秒探测次数
	// func NewLimiter(r Limit, b int) *Limiter
	// r   rate.Limit	令牌产生速率（每秒产生多少个令牌）
	// b   int	令牌桶大小（最多存储多少个令牌）
	limiter := rate.NewLimiter(rate.Limit(a.RateLimit), a.Burst) 

	sem := make(chan struct{}, a.Concurrency)

	for _, ip := range ips {

		wg.Add(1) // 增加 WaitGroup 计数器

		sem <- struct{}{} // 获取一个信号量，限制并发数量

		// 启动探活
		go func (ip string)  {

			defer wg.Done() // 在函数结束时减少 WaitGroup 计数器
			defer func() { <-sem }() // 释放信号量
			
			// 在每次探测前等待速率限制器允许，确保不超过设定的速率限制
			limiter.Wait(context.Background())

			if a.Jitter > 0 {
				
				// 计算基本延迟和最大抖动时间，增加探测的随机性，避免被防火墙等安全设备识别和阻止
				baseDelay := time.Second / time.Duration(a.RateLimit)

				// 计算最大抖动时间，基于基本延迟和用户设置的抖动比例
				maxJitter := time.Duration(float64(baseDelay) * a.Jitter)

				// 生成一个随机的抖动时间，范围在 0 到 maxJitter 之间
				jitter := time.Duration(rand.Int63n(int64(maxJitter)))

				// 等待基本延迟加上随机抖动时间，确保探测的时间具有随机性
				time.Sleep(baseDelay + jitter)
			}

			if icmpPing(ip, a.Timeout) {

				mu.Lock() // 加锁，确保对 results 切片的并发安全访问
				
				results = append(results, Result{
					Target: ip,
					Detail: "Host is alive",
				})
				mu.Unlock() // 解锁
			}
			
		}(ip) // 闭包变量捕获: 将 ip 作为参数传递给匿名函数，避免闭包问题
		// 异步执行 还没执行就继续了 等着执行的时候参数就变了，所以要传参
	}

	wg.Wait() // 等待所有 goroutine 完成

	return results, nil
}

