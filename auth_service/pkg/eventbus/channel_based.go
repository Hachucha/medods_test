package eventbus

import (
	"sync"
)

type ChannelBus[T any] struct {
	ch       chan T
	once     sync.Once
	closeMux sync.RWMutex
	closed   bool
}

func NewChannelBasedPublisher[T any](bufferSize int) *ChannelBus[T] {
	return &ChannelBus[T]{
		ch: make(chan T, bufferSize),
	}
}

func (p *ChannelBus[T]) Publish(event T) {
	p.closeMux.RLock()
	defer p.closeMux.RUnlock()

	if p.closed {
		// Канал закрыт, не публикуем событие
		return
	}

	// Публикация без блокировки — если буфер переполнен, событие дропается
	select {
	case p.ch <- event:
	default:
		// Можно логировать потерю события возмможно, пока я это не реализовал
	}
}

func (p *ChannelBus[T]) SetHandlingCycle(callback func(eventCh <-chan T)) {
	p.once.Do(func() {
		if callback == nil {
			return
		}
		go callback(p.ch);
	})
}

// Close безопасно закрывает канал и запрещает дальнейшую публикацию
func (p *ChannelBus[T]) Close() {
	p.closeMux.Lock()
	defer p.closeMux.Unlock()

	if !p.closed {
		close(p.ch)
		p.closed = true
	}
}
