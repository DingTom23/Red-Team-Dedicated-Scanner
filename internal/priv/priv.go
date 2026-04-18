package priv

import (
	"fmt"
	"net"
)

func HasRawSocket() bool {
	
	coon, err := net.Listen("ipv4:icmp", "0.0.0.0")



}