// engine 包提供了扫描引擎的实现
package engine

import (
    "context"
    "math/rand"
    "sync"
    "time"

    "github.com/DingTom23/Red-Team-Dedicated-Scanner/internal/config"
    "github.com/DingTom23/Red-Team-Dedicated-Scanner/internal/parse"
    "golang.org/x/time/rate"
)

// Engine 结构体定义了扫描引擎的配置
type Engine struct {
	Config config.ScanConfig
}

// NewEngine 创建一个新的扫描引擎实例，接受一个 ScanConfig 结构体作为参数，返回一个 Engine 指针
func NewEngine(config config.ScanConfig) *Engine {
	return &Engine{Config: config}
}

type ProbeFunc func(ip string, port int) *config.Result	

// Run 执行扫描模块，统一处理并发、限速、抖动
func (e *Engine) Run(probe ProbeFunc, targets []string, ports []int) ([]config.Result, error) {
	
	// goroutine   go 的轻量级线程，go func() 即可启动
	// channel   goroutine 之间传递数据的管道
	// sync.WaitGroup   等待一组 goroutine 完成 
	
	ips, err := parse.ParseTargets(targets)

	if err != nil {
		return nil, err
	}

	// 用于存储扫描结果
	var results []config.Result
	// 互斥锁，保护 results 切片的并发访问
	var mutex sync.Mutex
	// 等待组，用于等待所有 goroutine 完成
	var waitGroup sync.WaitGroup

	// 创建一个速率限制器，限制每秒探测次数
	// func NewLimiter(r Limit, b int) *Limiter
	// e.Config.RateLimit   rate.Limit	令牌产生速率（每秒产生多少个令牌）
	// e.Config.Burst   int	令牌桶大小（最多存储多少个令牌）
	limiter := rate.NewLimiter(rate.Limit(e.Config.RateLimit), e.Config.Burst)
	
	// 用于控制并发数的信号量

	// make(chan struct{})	创建一个 channel（管道）
	// chan struct{}	表示这个 channel 传输的数据类型是 struct{}
	// struct{} 是一个空结构体，占用零字节内存
	// make(chan struct{}, p.Concurrency)	
	// 创建一个带缓冲的 channel，缓冲大小为 p.Concurrency
	// 这个 channel 用作信号量来控制并发数
	sem := make(chan struct{}, e.Config.Concurrency) 
	
	// 构建扫描任务列表
	type task struct {
		ip string
		port int
	}
	var tasks []task

	if len(ports) == 0 {
        // 无端口 = 存活探测
        for _, ip := range ips {
            tasks = append(tasks, task{ip: ip})
        }
    } else {
        // 有端口 = 端口扫描
        for _, ip := range ips {
            for _, port := range ports {
                tasks = append(tasks, task{ip: ip, port: port})
            }
        }
    }

	// 打乱任务列表，增加扫描的随机性，避免被防火墙等安全设备识别和阻止
	rand.Shuffle(len(tasks), func(i, j int) {
		tasks[i], tasks[j] = tasks[j], tasks[i]
	})

	for _, t := range tasks {
		
		waitGroup.Add(1)
		sem <- struct{}{} // 获取一个信号量，限制并发数量



		go func (t task) {

			defer waitGroup.Done() // 在函数结束时减少 WaitGroup 计数器
			defer func() { <-sem }() // 释放信号量

			limiter.Wait(context.Background()) // 速率限制，等待允许发送请求

			if e.Config.Jitter > 0 {

				// 计算基本延迟和最大抖动时间，增加探测的随机性，避免被防火墙等安全设备识别和阻止
				baseDelay := time.Second / time.Duration(e.Config.RateLimit)
				
				// 计算最大抖动时间，基于基本延迟和用户设置的抖动比例
				maxJitter := time.Duration(float64(baseDelay) * e.Config.Jitter)

				// 生成一个随机的抖动时间，范围在 0 到 maxJitter 之间
				jitter := time.Duration(rand.Int63n(int64(maxJitter)))

				// 等待基本延迟加上随机抖动时间，确保探测的时间具有随机性
				time.Sleep(baseDelay + jitter)
			}

			result := probe(t.ip, t.port) // 调用探测函数，获取扫描结果

			if result != nil {
				mutex.Lock() // 加锁，确保对 results 切片的并发安全访问
				results = append(results, *result)
				mutex.Unlock()
			}

		}(t) // 闭包变量捕获: 将 t 作为参数传递给匿名函数，避免闭包问题

	}
	
	waitGroup.Wait() // 等待所有 goroutine 完成

	return results, nil
	
}