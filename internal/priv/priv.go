package priv

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
)

// HasRawSocket 检查当前用户是否具有创建原始套接字的权限
// 原始套接字权限 = 能发 ICMP/ARP/SYN 等底层包
// Linux 需要 root 或 CAP_NET_RAW，Windows 需要管理员
func HasRawSocket() bool {

	// 原理：尝试监听 ICMP 协议，成功说明有权限，失败说明没有
	conn, err := net.Listen("ipv4:icmp", "0.0.0.0")
	if err != nil {
		// 监听失败说明没有权限
		return false
	}

	// 监听成功说明有权限，关闭连接
	conn.Close()
	return true

}

// PS: 暂时不使用
// checkAdminWindows 使用 Windows API 检查当前用户是否具有管理员权限
func checkAdminWindows() bool {

	//原理：尝试创建一个命名管道，只有管理员才能创建成功
	pipeName := fmt.Sprintf(`\\.\pipe\scanner-admin-check-%d`, os.Getpid())
	
	// os.create 创建一个命名管道，如果创建成功说明有管理员权限
	f, err := os.Create(pipeName)
	if err != nil {
		return false
	}
	
	f.Close()
	return true
}

// PS: 暂时不使用
// isAdmin 检查当前用户是否具有管理员权限
func isAdmin() bool {

	switch runtime.GOOS {
		case "windows":
			return checkAdminWindows()
		case "linux", "darwin":
			return os.Geteuid() == 0
		default:
			return false
	}
	
}

// PS: 暂时不使用
// 在 Windows 下请求管理员权限
func RequireElevate() error {

	// 目前只支持 Windows 平台的自动提升，Linux 和 macOS 需要用户手动以 root 权限运行
	if runtime.GOOS != "windows" {
		return fmt.Errorf("auto-elevate only supported on Windows")
	}

	// 获取当前可执行文件路径
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	
	// 获取命令行参数
	args := os.Args[1:]

	// runas /user:Administrator 
	cmd := exec.Command("runas", "/user:Administrator", exe)
	cmd.Args = append(cmd.Args, args...)

	// 启动提升后的进程
	return cmd.Run()

}