package api

import (
	"context"
	"sync"
	"time"
)

type signalNotifier struct {
	mu    sync.Mutex
	nodes map[string]*signalNotifyState
}

type signalNotifyState struct {
	version uint64
	ch      chan struct{}
}

func newSignalNotifier() *signalNotifier {
	return &signalNotifier{
		nodes: make(map[string]*signalNotifyState),
	}
}

func (n *signalNotifier) version(nodeID string) uint64 {
	n.mu.Lock()
	defer n.mu.Unlock()

	return n.stateLocked(nodeID).version
}

func (n *signalNotifier) notify(nodeID string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	state := n.stateLocked(nodeID)
	state.version++
	close(state.ch)
	state.ch = make(chan struct{})
}

func (n *signalNotifier) wait(ctx context.Context, nodeID string, version uint64, timeout time.Duration) {
	n.mu.Lock()
	state := n.stateLocked(nodeID)
	if state.version != version {
		n.mu.Unlock()
		return
	}
	ch := state.ch
	n.mu.Unlock()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-ctx.Done():
	case <-ch:
	case <-timer.C:
	}
}

func (n *signalNotifier) stateLocked(nodeID string) *signalNotifyState {
	state := n.nodes[nodeID]
	if state == nil {
		state = &signalNotifyState{ch: make(chan struct{})}
		n.nodes[nodeID] = state
	}
	return state
}
