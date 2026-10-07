package engine

import (
	"fmt"
	"sort"
	"sync"
)

var (
	mu      sync.RWMutex
	engines = map[string]Engine{}
)

// Register makes an engine available under a config engine name. Engine
// packages call it from init; it panics on a duplicate or empty name.
func Register(name string, e Engine) {
	mu.Lock()
	defer mu.Unlock()
	if name == "" || e == nil {
		panic("engine: Register with an empty name or a nil engine")
	}
	if _, dup := engines[name]; dup {
		panic("engine: Register called twice for " + name)
	}
	engines[name] = e
}

// Get returns the engine registered under name.
func Get(engine string) (Engine, error) {
	mu.RLock()
	defer mu.RUnlock()
	if e, ok := engines[engine]; ok {
		return e, nil
	}
	return nil, fmt.Errorf("unknown engine %q", engine)
}

// Names lists the registered engine names, sorted.
func Names() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, 0, len(engines))
	for n := range engines {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
