package eventbus

import (
	sync "sync"
)

type ClassicBus[T any] struct {
	mu       sync.RWMutex
	callBacks []func(event T)
}

func (p *ClassicBus[T]) Subscribe(callBack func(event T)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.callBacks = append(p.callBacks, callBack)
}

func (p *ClassicBus[T]) Publish(event T) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, cb := range p.callBacks {
		go cb(event)
	}
}