package api

import "sync"

// waiters wakes long-polling fetches when an envelope arrives for their
// mailbox. Only in memory: nothing about who waits is ever persisted.
type waiters struct {
	mu sync.Mutex
	m  map[string]map[chan struct{}]struct{}
}

func newWaiters() *waiters {
	return &waiters{m: make(map[string]map[chan struct{}]struct{})}
}

// add registers a waiter for id. The returned channel is closed by notify;
// call the returned function to unregister.
func (w *waiters) add(id string) (<-chan struct{}, func()) {
	ch := make(chan struct{})
	w.mu.Lock()
	if w.m[id] == nil {
		w.m[id] = make(map[chan struct{}]struct{})
	}
	w.m[id][ch] = struct{}{}
	w.mu.Unlock()
	return ch, func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		if set, ok := w.m[id]; ok {
			if _, ok := set[ch]; ok {
				delete(set, ch)
				close(ch)
			}
			if len(set) == 0 {
				delete(w.m, id)
			}
		}
	}
}

func (w *waiters) notify(id string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for ch := range w.m[id] {
		close(ch)
	}
	delete(w.m, id)
}
