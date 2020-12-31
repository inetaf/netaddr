// Copyright 2020 The Inet.Af AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package netaddr

// uint128 represents a uint128 using two uint64s.
type uint128 struct {
	hi uint64
	lo uint64
}

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

// lastWithBitZero returns a copy of u with the given bit
// cleared and the following all set.
func (u uint128) lastWithBitZero(bit uint8) uint128 {
	u.clear(bit)
	for ; bit < 128; bit++ {
		u.set(bit)
	}
	return u
}

// firstWithBitOne returns a copy of u with the given bit
// set and the following all cleared.
func (u uint128) firstWithBitOne(bit uint8) uint128 {
	u.set(bit)
	for ; bit < 128; bit++ {
		u.clear(bit)
	}
	return u
}
