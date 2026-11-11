package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
)

// Ошибки валидации хостов
var (
	ErrEmptyHosts  = errors.New("portscan: список хостов не может быть пустым")
	ErrInvalidHost = errors.New("portscan: недопустимый или неразрешимый узел")
)

// target внутренняя структура, описывающая одну конкретную цель для сканирования
// Если у домена "типасайт.com" нашлось 2 разных IP-адреса, создаётся 2 структуры target
type target struct {
	host string
	ip   net.IP
}

// resolveTargets принимает сырой список строк хостов и превращает его в проверенный список целей
func resolveTargets(ctx context.Context, hosts []string) ([]target, error) {
	if len(hosts) == 0 {
		return nil, ErrEmptyHosts
	}

	seenHosts := make(map[string]struct{}, len(hosts))

	var targets []target

	for _, rawHost := range hosts {
		host := strings.TrimSpace(rawHost)

		if host == "" {
			return nil, fmt.Errorf("%w: host is empty", ErrInvalidHost)
		}

		if _, exists := seenHosts[host]; exists {
			continue
		}

		seenHosts[host] = struct{}{}

		if ip := net.ParseIP(host); ip != nil {
			targets = appendUniqueTarget(targets, host, ip)
			continue
		}

		if strings.Contains(host, "/") {
			cidrIPs, err := expandCIDR(host)
			if err != nil {
				return nil, fmt.Errorf("%w %q: %w", ErrInvalidHost, host, err)
			}
			for _, ip := range cidrIPs {
				targets = appendUniqueTarget(targets, host, ip)
			}
			continue
		}

		if strings.ContainsAny(host, " \t\n\\:") {
			return nil, fmt.Errorf("%w: malformed host %q", ErrInvalidHost, host)
		}

		ipAddrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("%w %q: %w", ErrInvalidHost, host, err)
		}

		if len(ipAddrs) == 0 {
			return nil, fmt.Errorf("%w: не найдено IP адресов для %q", ErrInvalidHost, host)
		}

		for _, addr := range ipAddrs {
			targets = appendUniqueTarget(targets, host, addr.IP)
		}
	}

	return targets, nil
}

// appendUniqueTarget добавляет цель в слайс только в том случае, если такой пары (host + IP) там ещё нет
func appendUniqueTarget(targets []target, host string, ip net.IP) []target {
	for _, t := range targets {
		if t.host == host && t.ip.Equal(ip) {
			return targets
		}
	}
	return append(targets, target{
		host: host,
		ip:   ip,
	})
}

// expandCIDR разворачивает CIDR маску (например 1.1.1.1/30) в список отдельных IP адресов
func expandCIDR(cidr string) ([]net.IP, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []net.IP

	for currentIP := cloneIP(ip.Mask(ipNet.Mask)); ipNet.Contains(currentIP); incrementIP(currentIP) {
		ips = append(ips, cloneIP(currentIP))
	}
	return ips, nil
}

func cloneIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
