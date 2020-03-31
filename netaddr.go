// Copyright 2020 The Inet.Af AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package netaddr contains an IP address type.
//
// This is a work in progress. See https://github.com/inetaf/netaddr for background.
package netaddr // import "inet.af/netaddr"

import (
	"errors"
	"fmt"
	"net"
)

// Sizes: (64-bit)
//   net.IP:     24 byte slice header + {4, 16} = 28 to 40 bytes
//   net.IPAddr: 40 byte slice header + {4, 16} = 44 to 56 bytes + zone length
//   netaddr.IP: 16 byte interface + {4, 16, 24} = 20, 32, 40 bytes + zone length

// IP represents an IPv4 or IPv6 address (with or without a scoped
// addressing zone), similar to Go's net.IP or net.IPAddr.
//
// Unlike net.IP or net.IPAddr, the netaddr.IP is a comparable value
// type (it supports == and can be a map key) and is immutable.
// Its memory representation ranges from 20 to 40 bytes, depending on
// whether the underlying adddress is IPv4, IPv6, or IPv6 with a
// zone. (This is smaller than the standard library's 28 to 56 bytes)
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

// IPAddr returns the net.IPAddr representation of an IP. The returned value is
// always non-nil, but the IPAddr.IP will be nil if ip is the zero value.
// If ip contains a zone identifier, IPAddr.Zone is populated.
func (ip IP) IPAddr() *net.IPAddr {
	switch ip := ip.ipImpl.(type) {
	case nil:
		// Nothing to do.
		return &net.IPAddr{}
	case v4Addr:
		return &net.IPAddr{IP: net.IP{ip[0], ip[1], ip[2], ip[3]}}
	case v6Addr:
		b := make(net.IP, net.IPv6len)
		copy(b, ip[:])

		return &net.IPAddr{IP: b}
	case v6AddrZone:
		b := make(net.IP, net.IPv6len)
		copy(b, ip.v6Addr[:])

		return &net.IPAddr{
			IP:   b,
			Zone: ip.zone,
		}
	default:
		panic("netaddr: unhandled ipImpl representation")
	}
}

// Is4 reports whether ip is an IPv4 address.
//
// TODO: decide/clarify the behavior for IPv4-mapped IPv6 addresses.
// They have different representations and are not equal with ==, but
// should a 4-in-6 address be Is4? Currently it's not. Maybe add As4?
// Go treats them as if they were the same (https://github.com/golang/go/issues/29146#issuecomment-454903818)
// but https://github.com/golang/go/issues/37921 requests more visibility into distinguishing them.
func (ip IP) Is4() bool {
	if ip.ipImpl == nil {
		return false
	}
	return ip.ipImpl.is4()
}

// Is6 reports whether ip is an IPv6 address.
//
// TODO: see same TODO for Is4.
func (ip IP) Is6() bool {
	if ip.ipImpl == nil {
		return false
	}
	return ip.ipImpl.is6()
}

// IsMulticast reports whether ip is a multicast address. If ip is the zero
// value, it will return false.
func (ip IP) IsMulticast() bool {
	// See: https://en.wikipedia.org/wiki/Multicast_address.
	switch ip := ip.ipImpl.(type) {
	case nil:
		return false
	case v4Addr:
		return ip[0]&0xf0 == 0xe0
	case v6Addr:
		return ip[0] == 0xff
	case v6AddrZone:
		return ip.v6Addr[0] == 0xff
	default:
		panic("netaddr: unhandled ipImpl representation")
	}
}

// String returns the string representation of ip.
func (ip IP) String() string {
	if ip.ipImpl == nil {
		return "invalid IP"
	}
	return ip.ipImpl.String()
}

// MarshalText implements the encoding.TextMarshaler interface,
// The encoding is the same as returned by String, with one exception:
// If ip is the zero value, the encoding is the empty string.
func (ip IP) MarshalText() ([]byte, error) {
	if ip.ipImpl == nil {
		return []byte(""), nil
	}
	return []byte(ip.String()), nil
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
// The IP address is expected in a form accepted by ParseIP.
// It returns an error if *ip is not the IP zero value.
func (ip *IP) UnmarshalText(text []byte) error {
	if ip.ipImpl != nil {
		return errors.New("netaddr: refusing to Unmarshal into non-zero IP")
	}
	if len(text) == 0 {
		return nil
	}
	var err error
	*ip, err = ParseIP(string(text))
	return err
}
