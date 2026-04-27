//go:build !windows && !linux

package module

import (
	"time"
)

func arpPing(target string, timeout time.Duration) bool {
	// 占位
	_ = timeout
	_ = target
	return false
}