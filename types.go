package portscan

import (
	"net"
	"time"
)

// State наш собственный тип на базе обычной строки
type State string

// Блок констант со всеми возможными состояниями
const (
	// StateOpen TCP соединение успешно установлено
	StateOpen State = "open"

	// StateClosed хост доступен, но явно отверг соединение
	StateClosed State = "closed"

	// StateTimeout удалённый узел ничего не ответил за отведённое время таймаута
	StateTimeout State = "timeout"

	// StateUnreachable сеть или сам хост недоступны
	StateUnreachable State = "unreachable"

	// StateCanceled сканирование было прервано пользователем
	StateCanceled State = "canceled"

	// StateError произошла любая иная неклассифицированная ошибка
	StateError State = "error"
)

// Result структура, содержащая итог проверки одного конкретного порта на одном IP
type Result struct {
	Host     string        // Исходная строка хоста, которую передал пользователь
	IP       net.IP        // Конкретный IP адрес, к которому реально выполнялось подключение
	Port     uint16        // Номер проверенного TCP порта
	State    State         // Итоговое состояние порта
	Duration time.Duration // Сколько времени заняла попытка подключения
	Err      error         // Сама ошибка подключения
}
