package main

import (
	"hash"
)

type CountingHash struct {
	h     hash.Hash
	count uint64
}

func (h *CountingHash) Write(p []byte) (int, error) {
	n, err := h.h.Write(p)

	h.count += uint64(n)

	return n, err
}

func (h *CountingHash) Sum(b []byte) []byte {
	return h.h.Sum(b)
}

func (h *CountingHash) Size() int {
	return h.h.Size()
}

func (h *CountingHash) BlockSize() int {
	return h.h.BlockSize()
}

func (h *CountingHash) Count() uint64 {
	return h.count
}

func NewCountingHash(h hash.Hash) *CountingHash {
	return &CountingHash{
		h,
		0,
	}
}
