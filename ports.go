package portscan

import (
	"errors"
	"fmt"
	"slices"
)

var (
	ErrEmptyPorts   = errors.New("portscan: список портов не может быть пустым")
	ErrInvalidPort  = errors.New("portscan: порт должен быть в диапазоне от 1 до 65535")
	ErrInvalidRange = errors.New("portscan: начальный порт не может быть больше конечного порта")
)

// PortSpec хранит внутри себя функцию-инструкцию
type PortSpec struct {
	build func() ([]uint16, error)
}

// Ports принимает любое количество отдельных номеров портов (например Ports(80 443 8080))
// Принимает тип int, чтобы перехватить числа меньшн или равно 0 и > 65535 в рантайме
func Ports(ports ...int) PortSpec {
	return PortSpec{
		build: func() ([]uint16, error) {

			if len(ports) == 0 {
				return nil, ErrEmptyPorts
			}

			res := make([]uint16, 0, len(ports))

			for _, p := range ports {

				if p < 1 || p > 65535 {
					return nil, fmt.Errorf("%w: got %d", ErrInvalidPort, p)
				}

				res = append(res, uint16(p))
			}

			return normalizePorts(res), nil
		},
	}
}

// Range задаёт диапазон портов от start до end включительно (например Range(1 1000))
func Range(start, end int) PortSpec {
	return PortSpec{
		build: func() ([]uint16, error) {

			if start < 1 || start > 65535 {
				return nil, fmt.Errorf("%w: start port %d", ErrInvalidPort, start)
			}

			if end < 1 || end > 65535 {
				return nil, fmt.Errorf("%w: end port %d", ErrInvalidPort, end)
			}

			if start > end {
				return nil, fmt.Errorf("%w: %d-%d", ErrInvalidRange, start, end)
			}

			count := end - start + 1
			res := make([]uint16, 0, count)

			for p := start; p <= end; p++ {
				res = append(res, uint16(p))
			}

			return res, nil
		},
	}
}

// Combine объединяет несколько правил PortSpec в одно
func Combine(specs ...PortSpec) PortSpec {
	return PortSpec{
		build: func() ([]uint16, error) {

			if len(specs) == 0 {
				return nil, ErrEmptyPorts
			}

			var combined []uint16

			for _, spec := range specs {

				if spec.build == nil {
					return nil, ErrEmptyPorts
				}

				ports, err := spec.build()
				if err != nil {
					return nil, err
				}

				combined = append(combined, ports...)
			}

			if len(combined) == 0 {
				return nil, ErrEmptyPorts
			}

			return normalizePorts(combined), nil
		},
	}
}

// resolve внутренний метод, который вызывает сам сканер для получения готового списка портов
func (ps PortSpec) resolve() ([]uint16, error) {
	if ps.build == nil {
		return nil, ErrEmptyPorts
	}
	return ps.build()
}

// normalizePorts сортирует слайс по возрастанию и удаляет повторяющиеся порты
func normalizePorts(ports []uint16) []uint16 {

	slices.Sort(ports)
	return slices.Compact(ports)
}
