package portscan

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func TestPortSpecValidation(t *testing.T) {
	if _, err := Ports(0).resolve(); !errors.Is(err, ErrInvalidPort) {
		t.Fatalf("ожидалось ErrInvalidPort для порта 0, получено %v", err)
	}

	if _, err := Ports(65536).resolve(); !errors.Is(err, ErrInvalidPort) {
		t.Fatalf("ожидалась ошибка ErrInvalidPort для порта 65536, получено %v", err)
	}

	if _, err := Range(1000, 1).resolve(); !errors.Is(err, ErrInvalidRange) {
		t.Fatalf("Ожидалась ошибка ErrInvalidRange для диапазона 1000-1, получена ошибка %v", err)
	}

	if _, err := Ports().resolve(); !errors.Is(err, ErrEmptyPorts) {
		t.Fatalf("ожидалась ошибка ErrEmptyPorts, got %v", err)
	}

	ports, err := Combine(Range(80, 82), Ports(81, 443, 80)).resolve()
	if err != nil {
		t.Fatalf("непредвиденная ошибка: %v", err)
	}
	expected := []uint16{80, 81, 82, 443}
	if len(ports) != len(expected) {
		t.Fatalf("expected %v, got %v", expected, ports)
	}
	for i := range expected {
		if ports[i] != expected[i] {
			t.Fatalf("по индексу %d: ожидалось %d, получено %d", i, expected[i], ports[i])
		}
	}
}

func TestTargetValidation(t *testing.T) {
	ctx := context.Background()

	if _, err := resolveTargets(ctx, nil); !errors.Is(err, ErrEmptyHosts) {
		t.Fatalf("expected ErrEmptyHosts, got %v", err)
	}

	if _, err := resolveTargets(ctx, []string{"   "}); !errors.Is(err, ErrInvalidHost) {
		t.Fatalf("expected ErrInvalidHost for empty string, got %v", err)
	}

	targets, err := resolveTargets(ctx, []string{"127.0.0.1", "127.0.0.1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 deduplicated target, got %d", len(targets))
	}
}

func TestScanOpenAndClosedPorts(t *testing.T) {
	openListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer openListener.Close()

	go func() {
		for {
			conn, err := openListener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	openPort := openListener.Addr().(*net.TCPAddr).Port

	closedListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for closed port: %v", err)
	}
	closedPort := closedListener.Addr().(*net.TCPAddr).Port
	_ = closedListener.Close()

	scanner, err := New(
		WithConcurrency(10),
		WithConnectTimeout(500*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}

	resultsCh, err := scanner.Scan(
		context.Background(),
		[]string{"127.0.0.1"},
		Ports(openPort, closedPort),
	)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	gotStates := make(map[uint16]State)
	for res := range resultsCh {
		gotStates[res.Port] = res.State
	}

	if gotStates[uint16(openPort)] != StateOpen {
		t.Errorf("expected port %d to be %s, got %s", openPort, StateOpen, gotStates[uint16(openPort)])
	}
	if gotStates[uint16(closedPort)] != StateClosed {
		t.Errorf("expected port %d to be %s, got %s", closedPort, StateClosed, gotStates[uint16(closedPort)])
	}
}

func TestContextCancellationAndSlowReader(t *testing.T) {
	scanner, err := New(
		WithConcurrency(5),
		WithConnectTimeout(200*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("непредвиденная ошибка: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	results, err := scanner.Scan(ctx, []string{"127.0.0.1"}, Range(1, 2000))
	if err != nil {
		t.Fatalf("ошибка сканирования: %v", err)
	}

	<-results
	cancel()

	done := make(chan struct{})
	go func() {
		for range results {
		}
		close(done)
	}()

	select {
	case <-done:

	case <-time.After(3 * time.Second):
		t.Fatal("сканер завис после отмены контекста")
	}
}

func TestScannerConcurrentReuse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port

	scanner, err := New(WithConcurrency(4), WithConnectTimeout(300*time.Millisecond))
	if err != nil {
		t.Fatalf("не удалось создать сканер: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resCh, err := scanner.Scan(context.Background(), []string{"127.0.0.1"}, Ports(port))
			if err != nil {
				t.Errorf("неожиданная ошибка: %v", err)
				return
			}
			for res := range resCh {
				if res.State != StateOpen {
					t.Errorf("ожидалось StateOpen, получено %s", res.State)
				}
			}
		}()
	}
	wg.Wait()
}
