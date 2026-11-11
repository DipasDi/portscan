package portscan

import (
	"errors"
	"time"
)

// Значения по умолчанию
const (
	defaultConcurrency    = 100             // По умолчанию максимум 100 одновременных подключений
	defaultConnectTimeout = 1 * time.Second // По умолчанию ожидание ответа от порта 1 секунда
)

// Предопределённые ошибки конфигурации сканера
var (
	ErrInvalidConcurrency = errors.New("portscan: параллелизм должен быть больше 0")
	ErrInvalidTimeout     = errors.New("portscan: тайм-аут подключения должен быть больше 0")
)

// Option это тип функции которая принимает указатель на Scanner
type Option func(*Scanner) error

// Scanner главная структура пакета
type Scanner struct {
	concurrency    int           // Лимит одновременно работающих горутин
	connectTimeout time.Duration // Таймаут на одно TCP подключение
}

// New функция конструктор. Создаёт и возвращает указатель на новый Scanner
func New(opts ...Option) (*Scanner, error) {
	s := &Scanner{
		concurrency:    defaultConcurrency,
		connectTimeout: defaultConnectTimeout,
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(s); err != nil {
			return nil, err
		}
	}

	return s, nil
}

// WithConcurrency функция, которая возвращает Option для установки лимита горутин
func WithConcurrency(n int) Option {
	return func(s *Scanner) error {
		if n <= 0 {
			return ErrInvalidConcurrency
		}

		s.concurrency = n
		return nil
	}
}

// WithConnectTimeout функция, которая возвращает Option для установки таймаута подключения
func WithConnectTimeout(d time.Duration) Option {
	return func(s *Scanner) error {
		if d <= 0 {
			return ErrInvalidTimeout
		}
		s.connectTimeout = d
		return nil
	}
}
