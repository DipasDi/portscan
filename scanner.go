package portscan

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"
)

// job описывает одну элементарную задачу для воркера: проверить один порт на одном IP
type job struct {
	target target
	port   uint16
}

// Scan запускает конкурентное сканирование заданных хостов и портов
func (s *Scanner) Scan(ctx context.Context, hosts []string, portSpec PortSpec) (<-chan Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	ports, err := portSpec.resolve()
	if err != nil {
		return nil, err
	}

	targets, err := resolveTargets(ctx, hosts)
	if err != nil {
		return nil, err
	}

	totalJobs := len(targets) * len(ports)

	workerCount := s.concurrency
	if totalJobs < workerCount {
		workerCount = totalJobs
	}
	if workerCount < 1 {
		workerCount = 1
	}

	jobs := make(chan job, workerCount)
	results := make(chan Result, workerCount)

	go func() {
		defer close(jobs)

		for _, t := range targets {
			for _, port := range ports {

				if ctx.Err() != nil {
					return
				}

				select {
				case <-ctx.Done():
					return
				case jobs <- job{target: t, port: port}:
				}
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(workerCount)

	for i := 0; i < workerCount; i++ {
		go func() {

			defer wg.Done()

			for j := range jobs {
				res := s.probe(ctx, j.target, j.port)

				select {
				case results <- res:
				case <-ctx.Done():

					select {
					case results <- res:
					default:
					}
					return
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	return results, nil
}

func (s *Scanner) probe(ctx context.Context, t target, port uint16) Result {
	if err := ctx.Err(); err != nil {
		return Result{
			Host:  t.host,
			IP:    t.ip,
			Port:  port,
			State: StateCanceled,
			Err:   err,
		}
	}

	address := net.JoinHostPort(t.ip.String(), strconv.Itoa(int(port)))

	dialer := net.Dialer{
		Timeout: s.connectTimeout,
	}

	start := time.Now()

	conn, err := dialer.DialContext(ctx, "tcp", address)

	duration := time.Since(start)

	if conn != nil {
		_ = conn.Close()
	}

	state := classifyError(ctx, err)

	return Result{
		Host:     t.host,
		IP:       t.ip,
		Port:     port,
		State:    state,
		Duration: duration,
		Err:      err,
	}
}
