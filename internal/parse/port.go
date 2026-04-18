// 端口解析器，支持多种格式的端口输入，如单个端口、逗号分隔的端口列表和端口范围
package parse

import (
	"fmt"
	"strconv"
	"strings"
)

// ParsePorts 解析端口字符串，支持多种格式
func ParsePorts(portStr string) ([]int, error) {

	var ports []int
	
	// 用于检查端口是否重复
	seen := make(map[int]bool)

	// 将输入的端口字符串按逗号分割，支持多种格式，如 "80,443,8080-8089" 或 "80-90"
	parts := strings.Split(portStr, ",")

	// 遍历每个部分，处理单个端口和端口范围
	for _, part := range parts {
		
		// 去除空格，避免因为输入错误而导致的解析错误
		part = strings.TrimSpace(part)

		// 如果部分包含 - 字符，表示一个端口范围
		if strings.Contains(part, "-") {
			
			// 按 - 分割范围
			rangeParts := strings.Split(part, "-")

			// 检查是不是有两个部分
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}

			// strconv.Atoi() 把字符串转成整数
			// 解析范围的起始和结束端口
			start, err := strconv.Atoi(rangeParts[0])
			if err != nil {
				return nil, fmt.Errorf("invalid start port: %s", rangeParts[0])
			}

			// 解析范围的结束端口
			end, err := strconv.Atoi(rangeParts[1])
			if err != nil {
				return nil, fmt.Errorf("invalid end port: %s", rangeParts[1])
			}

			// 检查起始端口是否小于或等于结束端口
			if start > end {
				return nil, fmt.Errorf("start port must be less than or equal to end port: %s", part)
			}

			// 将 "-" 的所有端口添加到列表中，避免重复
			for i := start; i <= end; i++ {
				if !seen[i] {
					ports = append(ports, i)
					seen[i] = true
				}
			}

		} else {
			// 解析单个端口
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", part)
			}

			// 添加单个端口到列表中，避免重复
			if !seen[port] {
				ports = append(ports, port)
				seen[port] = true
			}
		}
	}

	return ports, nil

}