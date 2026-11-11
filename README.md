# portscan Пакет конкурентного TCP сканирования портов на Go

Легковесный Go пакет для конкурентной проверки доступности TCP портов с использованием только стандартной библиотеки Go (1.25+)

## Тестирование

```bash
go test -v ./...
# или с проверкой race conditions:
go test -race ./...
```

## Пример использования

Запуск примера:
```bash
go run ./examples/main.go
```

```go
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/DipasDi/portscan"
)

func main() {
	scanner, err := portscan.New(
		portscan.WithConcurrency(100),
		portscan.WithConnectTimeout(500*time.Millisecond),
	)
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ports := portscan.Combine(
		portscan.Range(1, 1000),
		portscan.Ports(8080, 8443),
	)

	results, err := scanner.Scan(ctx, []string{"127.0.0.1", "localhost"}, ports)
	if err != nil {
		panic(err)
	}

	for res := range results {
		fmt.Printf("%s (%s):%d -> %s (%v)\n", res.Host, res.IP, res.Port, res.State, res.Duration)
	}
}
```

## Устройство публичного API и принятые проектные решения

### Конфигурация сканера

- `New(opts ...Option) (*Scanner, error)` создаёт потокобезопасный экземпляр сканера. Экземпляр не хранит изменяемого состояния между запусками, поэтому его можно безопасно использовать конкурентно из нескольких горутин
- `WithConcurrency(n int)` задаёт максимальное число одновременных TCP подключений (при `n <= 0` возвращается `ErrInvalidConcurrency`)
- `WithConnectTimeout(d time.Duration)` задаёт таймаут на установку одного TCPсоединения (при `d <= 0` возвращается `ErrInvalidTimeout`)

### Задание портов (`PortSpec`)

- `Ports(ports ...int)` список отдельных портов
- `Range(start, end int)` включительный диапазон портов
- `Combine(specs ...PortSpec)` объединение произвольного числа диапазонов и списков портов

- **Поведение в пограничных случаях:**
  - Порт `0`, отрицательные порты и порты `> 65535` возвращают ошибку `ErrInvalidPort` до старта сканирования
  - Обратный диапазон (например, `1000–1`) возвращает ошибку `ErrInvalidRange`
  - Пустой список портов возвращает `ErrEmptyPorts`
  - Дублирующиеся порты автоматически дедуплицируются и сортируются по возрастанию

### Обработка целей (Хостов)

- Поддерживаются IPv4, IPv6, DNS-имена и CIDR-подсети (например, `192.168.1.0/24`)
- **Поведение в пограничных случаях**
  - Пустой список хостов возвращает `ErrEmptyHosts`
  - Пустая строка, некорректный адрес или неразрешимое DNS имя возвращают ошибку `ErrInvalidHost` на этапе инициализации `Scan`
  - Повторяющиеся хосты и одинаковые пары `(Host, IP)` автоматически дедуплицируются
  - Если одному DNS имени соответствует несколько IP адресов (A / AAAA записи), сканирование выполняется для каждого уникального IP адреса

### Состояния портов (`State`)

Определение состояний выполняется строго через типизированные ошибки (`errors.Is`, `errors.As`, `net.Error`, `syscall.Errno`) без парсинга текста ошибок:

- `StateOpen` (`"open"`) TCP соединение успешно установлено и сразу корректно закрыто
- `StateClosed` (`"closed"`) получено явное отклонение соединения (`ECONNREFUSED`)
- `StateTimeout` (`"timeout"`) истёк таймаут подключения `WithConnectTimeout`
- `StateUnreachable` (`"unreachable"`) сеть или хост недоступны (`EHOSTUNREACH`, `ENETUNREACH`, `ENETDOWN`, `EHOSTDOWN`)
- `StateCanceled` (`"canceled"`) операция отменена через переданный `context.Context`
- `StateError` (`"error"`) любая прочая ошибка
