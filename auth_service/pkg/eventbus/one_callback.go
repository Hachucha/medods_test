package eventbus

import (
	"sync"
)

type OneCallbackBus[T any] struct {
	mu       sync.RWMutex
	callBack func(event T)
}

func (p *OneCallbackBus[T]) SetCallBack(callBack func(event T)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.callBack = callBack
}

func (p *OneCallbackBus[T]) Publish(event T) {
	p.mu.RLock()
	cb := p.callBack
	p.mu.RUnlock()

	if cb != nil {
		go cb(event)
	}
}



