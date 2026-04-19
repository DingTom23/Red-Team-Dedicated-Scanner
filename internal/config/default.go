package config

var DefaultTCPPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
	143, 443, 445, 993, 995, 1433, 1521, 2049,
	3306, 3389, 5432, 5900, 6379, 8080, 8443,
	9200, 27017,
}

var DefaultPortsforAliveScan = []int{
	22, 80, 443, 445, 3306, 3389,
}

var AllPorts = []int{}

// init() 是 Go 的特殊函数，包被导入时自动执行，不需要手动调用
// 它用于初始化包级别的变量，这里用于初始化 AllPorts 切片
func init() {
	for i := 0; i <= 65535; i++ {
		AllPorts = append(AllPorts, i)
	}
}

