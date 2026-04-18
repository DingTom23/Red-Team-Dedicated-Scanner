// Package config 定义了扫描模块的通用配置结构体和扫描结果结构体，以及所有扫描模块必须实现的接口

package config

import (
	"time"
)

// ScanConfig 是所有扫描模块的通用配置结构体，包含了并发数量、超时时间、速率限制等参数
type ScanConfig struct {

    // 并发数量 / 控制同时探测的主机数量
	Concurrency int 

	// 探测超时时间
	Timeout time.Duration 

	// 速率限制 / 每秒探测次数
	RateLimit int 

	// 速率限制的突发值 / 允许短时间内超过速率限制的请求数量
	Burst int

	// 时钟抖动 / 探测时间的随机抖动，增加探测的随机性，避免被防火墙等安全设备识别和阻止 
	Jitter float64

}

// Result 结构体定义了扫描结果的格式，包含目标地址、端口号、服务信息等字段
type Result struct {
	Target string
	Port int
	Service string
	Version string
	Detail string
}

// Module 接口定义了所有扫描模块的通用方法
// 所有扫描模块都必须实现这个接口
type Module interface {
	
	// 方法签名，大写表示导出
	// 调用方式是 某个模块.Name()
	Name() string

	// 传入 targets 是参数名 ，[]string 是参数类型，表示一个字符串切片
	// 返回 []Result 是我们定义的结构体的切片
	Run(targets []string) ([]Result, error)
}

