package main

import "sync"

// Readers and queued writers own separate buffers. The reader can recycle its
// input as soon as the destination has taken ownership of the encoded frame.
type frameStorage struct {
	bytes []byte
	pool  *sync.Pool
}

var ordinaryFrames = sync.Pool{New: func() any { return &frameStorage{bytes: make([]byte, 2048)} }}
var extendedFrames = sync.Pool{New: func() any { return &frameStorage{bytes: make([]byte, frameHeader+65535)} }}

func acquireFrame(size int) *frameStorage {
	pool := &ordinaryFrames
	if size > 2048 {
		pool = &extendedFrames
	}
	store := pool.Get().(*frameStorage)
	store.bytes = store.bytes[:size]
	store.pool = pool
	return store
}

func (store *frameStorage) release() {
	if store != nil {
		store.pool.Put(store)
	}
}
