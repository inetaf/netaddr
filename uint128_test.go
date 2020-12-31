// Copyright 2020 The Inet.Af AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package netaddr

import (
	"fmt"
	"math/rand"
	"testing"
)

// bitSet reports whether the given bit in the address is set.
// (bit 0 is the most significant bit in ip[0]; bit 127 is last)
// Results undefined for invalid bit numbers.
func (u uint128) bitSet(bit uint8) bool {
	hli := (bit / 64) % 2 // hi/lo index: 0 or 1, respectively
	s := 63 - (bit % 64)
	return *(u.halves()[hli])&(1<<s) != 0
}

func TestUint128(t *testing.T) {
	randU128 := func() (uint128, string) {
		var a [16]byte
		rand.Read(a[:])
		u := ipv6Slice(a[:]).addr
		return u, fmt.Sprintf("%064b%064b", u.hi, u.lo)
	}

	u128, bitStr := randU128()
	for bit := uint8(0); bit < 128; bit++ {
		set, want := u128.bitSet(bit), bitStr[bit] == '1'
		if set != want {
			t.Fatalf("bitSet(%d) wrong", bit)
		}
	}
	for bit := uint8(0); bit < 128; bit++ {
		set := u128.bitSet(bit)
		if set {
			u128.clear(bit)
		} else {
			u128.set(bit)
		}
		newSet := u128.bitSet(bit)
		if newSet == set {
			t.Fatalf("bit(%d) set/clear from %v to %v failed", bit, set, !set)
		}
	}
}
