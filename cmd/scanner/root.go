package main

import (
    "fmt"
    "os"
    "time"

    "github.com/spf13/cobra"
)

// Root Command / go 没有继承，只有组合 
var rootCmd = &cobra.Command{
    Use:   "scanner",
    Short: "Internal network detector",
}


var (
    target      string
    concurrency int
    timeout     time.Duration
    rateLimit   int
    burst       int
    jitter      float64
)


func exitError(err error) {
    fmt.Fprintln(os.Stderr, err)
    os.Exit(1)
}