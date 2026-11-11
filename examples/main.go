package main

import (
	"context"
	"fmt"
	"time"

	"github.com/DipasDi/portscan"
)

func main() {
	scanner, err := portscan.New(
		portscan.WithConcurrency(20),
		portscan.WithConnectTimeout(500*time.Millisecond),
	)
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ports := portscan.Combine(
		portscan.Range(78, 85),
		portscan.Ports(443, 8080),
	)

	results, err := scanner.Scan(ctx, []string{"127.0.0.1"}, ports)
	if err != nil {
		panic(err)
	}

	for res := range results {
		fmt.Printf("Порт %-5d -> %-10s (%v)\n", res.Port, res.State, res.Duration)
	}
}
