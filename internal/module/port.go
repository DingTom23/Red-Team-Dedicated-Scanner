// 端口扫描模块的实现
package module

import (
	"net"
	"strconv"
	"time"

	"github.com/DingTom23/Red-Team-Dedicated-Scanner/internal/config"
	"github.com/DingTom23/Red-Team-Dedicated-Scanner/internal/engine"
)

// PortModule 结构体定义了端口扫描模块的配置
type PortModule struct {
	
	// 嵌入 ScanConfig 结构体，继承其字段
	config.ScanConfig // 嵌入 ScanConfig 结构体，继承其字段

	// 需要扫描的端口列表
	Ports []int 
}

// Name 方法返回模块的名称，满足 Module 接口的要求
func (p PortModule) Name() string {
	return "port"
}


// TCP 探测

// 单个端口的 TCP 探测方法
// 接收者p  方法名TCP  传入参数：目标地址、端口号、超时时间 返回值：bool
func (p PortModule) tcpConnected(target string, port int, timeout time.Duration) bool {
	
	// net.JoinHostPort() 函数将主机地址和端口号组合成一个地址字符串，格式为 "host:port"
	address := net.JoinHostPort(target, strconv.Itoa(port)) // Integer to ASCII

	// 尝试建立 TCP 连接
	// net.DialTimeout() 函数用于在指定的超时时间内尝试连接到目标地址
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false
	}

	conn.Close()
	return true
}

func (p PortModule) Run(targets []string) ([]config.Result, error) {
	
	e := engine.NewEngine(p.ScanConfig)

	probe := func(ip string, port int) *config.Result {
		
		if p.tcpConnected(ip, port, p.Timeout) {
			return &config.Result{Target: ip, Port: port, Detail: "Port is open."}
		}
		
		return nil
	}

	return e.Run(probe, targets, nil)

}