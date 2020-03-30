// Copyright 2020 The Inet.Af AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package netaddr contains an IP address type.
package netaddr

import (
	"fmt"
	"net"
)

// Sizes: (64-bit)
//   net.IP:     24 byte slice header + {4, 16} = 28 to 40 bytes
//   net.IPAddr: 40 byte slice header + {4, 16} = 44 to 56 bytes + zone length
//   netaddr.IP: 16 byte interface + {4, 16, 24} = 20, 32, 40 bytes + zone length

// IP represents an IPv4 or IPv6 address (with or without a scoped
// addressing zone), similar to Go's net.IPAddr.
//
// Unlike net.IPAddr, is a comparable value type (it supports == and can be a map key), and it's immutable. It's
// memory representation ranges from 20 to 40 bytes, depending on
// whether the underlying adddress is IPv4, IPv6, or IPv6 with a zone.
//
// Being a comparable value type, it supports == and being used as a
// map key.
type IP struct {
	ipImpl
}

// ipImpl is the interface representing either a v4addr, v6addr, v6ZoneAddr.
type ipImpl interface {
	is4() bool
	is6() bool
	String() string
}

type v4Addr [4]byte

func (v4Addr) is4() bool         { return true }
func (v4Addr) is6() bool         { return false }
func (ip v4Addr) String() string { return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]) }

type v6Addr [16]byte

func (v6Addr) is4() bool { return false }
func (v6Addr) is6() bool { return true }
func (ip v6Addr) String() string {
	// TODO: better implementation
	return (&net.IPAddr{IP: net.IP(ip[:])}).String()
}

type v6AddrZone struct {
	v6Addr
	zone string
}

func (ip v6AddrZone) String() string {
	// TODO: better implementation
	return (&net.IPAddr{IP: net.IP(ip.v6Addr[:]), Zone: ip.zone}).String()
}

// ParseIP parses s as an IP address, returning the result. The string
// s can be in dotted decimal ("192.0.2.1"), IPv6 ("2001:db8::68"),
// or IPv6 with a scoped addressing zone ("fe80::1cc0:3e8c:119f:c2e1%ens18").
func ParseIP(s string) (IP, error) {
	// TODO: do our own parsing to save some allocs? For now,
	// while showing off new API & representation, just use the
	// standard library's parsing.
	ipa, err := net.ResolveIPAddr("ip", s)
	if err != nil {
		return IP{}, err
	}
	if ip4 := ipa.IP.To4(); ip4 != nil {
		var v4 v4Addr
		copy(v4[:], ip4)
		return IP{v4}, nil
	}
	var v6 v6Addr
	copy(v6[:], ipa.IP.To16())
	if ipa.Zone != "" {
		return IP{v6AddrZone{v6, ipa.Zone}}, nil
	}
	return IP{v6}, nil
}

// Is4 reports whether ip is an IPv4 address.
func (ip IP) Is4() bool { return ip.ipImpl.is4() }

// Is6 reports whether ip is an IPv6 address.
func (ip IP) Is6() bool { return ip.ipImpl.is6() }

// String returns the string representation of ip.
func (ip IP) String() string {
	return ip.ipImpl.String()
}
