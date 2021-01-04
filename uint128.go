// Copyright 2020 The Inet.Af AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package netaddr

import "math/bits"

// uint128 represents a uint128 using two uint64s.
//
// When the methods below mention a bit number, bit 0 is the most
// significant bit (in hi) and bit 127 is the lowest (lo&1).
type uint128 struct {
	hi uint64
	lo uint64
}

// isZero reports whether u == 0.
//
// It's faster than u == (uint128{}) because the compiler (as of Go
// 1.15/1.16b1) doesn't do this trick and instead inserts a branch in
// its eq alg's generated code.
func (u uint128) isZero() bool { return u.hi|u.lo == 0 }

// and returns the bitwise AND of u and m (u&m).
func (u uint128) and(m uint128) uint128 {
	return uint128{u.hi & m.hi, u.lo & m.lo}
}

// xor returns the bitwise XOR of u and m (u^m).
func (u uint128) xor(m uint128) uint128 {
	return uint128{u.hi ^ m.hi, u.lo ^ m.lo}
}

// or returns the bitwise OR of u and m (u|m).
func (u uint128) or(m uint128) uint128 {
	return uint128{u.hi | m.hi, u.lo | m.lo}
}

// subOne returns u - 1.
func (u uint128) subOne() uint128 {
	lo, borrow := bits.Sub64(u.lo, 1, 0)
	return uint128{u.hi - borrow, lo}
}

// addOne returns u + 1.
func (u uint128) addOne() uint128 {
	lo, carry := bits.Add64(u.lo, 1, 0)
	return uint128{u.hi + carry, lo}
}

func u64CommonPrefixLen(a, b uint64) uint8 {
	for i := uint8(0); i < 64; i++ {
		if a == b {
			return 64 - i
		}
		a >>= 1
		b >>= 1
	}
	return 0
}

func (a uint128) commonPrefixLen(b uint128) (n uint8) {
	if n = u64CommonPrefixLen(a.hi, b.hi); n == 64 {
		n += u64CommonPrefixLen(a.lo, b.lo)
	}
	return
}

func (u *uint128) halves() [2]*uint64 {
	return [2]*uint64{&u.hi, &u.lo}
}

func (u *uint128) set(bit uint8) {
	hli := (bit / 64) % 2 // hi/lo index: 0 or 1, respectively
	s := 63 - (bit % 64)
	*(u.halves()[hli]) |= 1 << s
}

func (u *uint128) clear(bit uint8) {
	hli := (bit / 64) % 2 // hi/lo index: 0 or 1, respectively
	s := 63 - (bit % 64)
	*(u.halves()[hli]) &^= 1 << s
}

// bitsSetFrom returns a copy of u with the given bit
// and all subsequent ones set.
func (u uint128) bitsSetFrom(bit uint8) uint128 {
	if bit <= 64 {
		u.hi |= 1<<(64-bit) - 1
		u.lo = ^uint64(0)
	} else {
		u.lo |= 1<<(128-bit) - 1
	}
	return u
}

// bitsClearedFrom returns a copy of u with the given bit
// and all subsequent ones cleared.
func (u uint128) bitsClearedFrom(bit uint8) uint128 {
	if bit <= 64 {
		u.hi >>= 64 - bit
		u.hi <<= 64 - bit
		u.lo = 0
	} else {
		u.lo >>= 128 - bit
		u.lo <<= 128 - bit
	}
	return u
}
