// Copyright 2020 The Inet.Af AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package netaddr contains an IP address type.
//
// This is a work in progress. See https://github.com/inetaf/netaddr for background.
package netaddr // import "inet.af/netaddr"

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
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
	is4in6() bool
	as16() [16]byte
	String() string
}

type v4Addr [4]byte

func (v4Addr) is4() bool    { return true }
func (v4Addr) is6() bool    { return false }
func (v4Addr) is4in6() bool { return false }
func (ip v4Addr) as16() [16]byte {
	return [16]byte{
		10: 0xff,
		11: 0xff,
		12: ip[0],
		13: ip[1],
		14: ip[2],
		15: ip[3],
	}
}
func (ip v4Addr) String() string { return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]) }

// mapped4Prefix are the 12 leading bytes in a IPv4-mapped IPv6 address.
const mapped4Prefix = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff"

type v6Addr [16]byte

func (v6Addr) is4() bool         { return false }
func (v6Addr) is6() bool         { return true }
func (ip v6Addr) is4in6() bool   { return string(ip[:len(mapped4Prefix)]) == mapped4Prefix }
func (ip v6Addr) as16() [16]byte { return ip }
func (ip v6Addr) String() string {
	// TODO: better implementation; don't jump through these hoops
	// and pay these allocs just to share a bit of code with
	// std. Just copy & modify it as needed.
	if ip.is4in6() {
		mod := ip
		mod[10] = 0xfe // change to arbitrary byte that's not 0xff to hide it from Go
		s := net.IP(mod[:]).String()
		return strings.Replace(s, "::feff:", "::ffff:", 1)
	}
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

// IPv4 returns the IP of the IPv4 address a.b.c.d.
func IPv4(a, b, c, d uint8) IP {
	return IP{v4Addr{a, b, c, d}}
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
	if !strings.Contains(s, ":") {
		if ip4 := ipa.IP.To4(); ip4 != nil {
			var v4 v4Addr
			copy(v4[:], ip4)
			return IP{v4}, nil
		}
	}
	var v6 v6Addr
	copy(v6[:], ipa.IP.To16())
	if ipa.Zone != "" {
		return IP{v6AddrZone{v6, ipa.Zone}}, nil
	}
	return IP{v6}, nil
}

// Zone returns ip's IPv6 scoped addressing zone, if any.
func (ip IP) Zone() string {
	if v6z, ok := ip.ipImpl.(v6AddrZone); ok {
		return v6z.zone
	}
	return ""
}

// Less reports whether ip sorts before ip2.
// IP addresses sort first by length, then their address.
// IPv6 addresses with zones sort just after the same address without a zone.
func (ip IP) Less(ip2 IP) bool {
	a, b := ip, ip2
	// Zero value sorts first.
	if a.ipImpl == nil {
		return b.ipImpl != nil
	}
	if b.ipImpl == nil {
		return false
	}

	// At this point, a and b are both either v4 or v6.

	if a4, ok := a.ipImpl.(v4Addr); ok {
		if b4, ok := b.ipImpl.(v4Addr); ok {
			return bytes.Compare(a4[:], b4[:]) < 0
		}
		// v4 sorts before v6.
		return true
	}

	// At this point, a and b are both v6 or v6+zone.
	a16 := a.ipImpl.as16()
	b16 := b.ipImpl.as16()
	switch bytes.Compare(a16[:], b16[:]) {
	case -1:
		return true
	default:
		return a.Zone() < b.Zone()
	case 1:
		return false
	}
}

func (ip IP) ipZone() (stdIP net.IP, zone string) {
	switch ip := ip.ipImpl.(type) {
	case nil:
		return nil, ""
	case v4Addr:
		return net.IP{ip[0], ip[1], ip[2], ip[3]}, ""
	case v6Addr:
		stdIP = make(net.IP, net.IPv6len)
		copy(stdIP, ip[:])
		return stdIP, ""
	case v6AddrZone:
		stdIP = make(net.IP, net.IPv6len)
		copy(stdIP, ip.v6Addr[:])
		return stdIP, ip.zone
	default:
		panic("netaddr: unhandled ipImpl representation")
	}
}

// IPAddr returns the net.IPAddr representation of an IP. The returned value is
// always non-nil, but the IPAddr.IP will be nil if ip is the zero value.
// If ip contains a zone identifier, IPAddr.Zone is populated.
func (ip IP) IPAddr() *net.IPAddr {
	stdIP, zone := ip.ipZone()
	return &net.IPAddr{IP: stdIP, Zone: zone}
}

// Is4 reports whether ip is an IPv4 address.
//
// It returns false for IP4-mapped IPv6 addresses. See IP.Unmap.
func (ip IP) Is4() bool {
	if ip.ipImpl == nil {
		return false
	}
	return ip.ipImpl.is4()
}

// Is4in6 reports whether ip is an IPv4-mapped IPv6 address.
func (ip IP) Is4in6() bool {
	if ip.ipImpl == nil {
		return false
	}
	return ip.ipImpl.is4in6()
}

// Is6 reports whether ip is an IPv6 address, including IPv4-mapped
// IPv6 addresses.
func (ip IP) Is6() bool {
	if ip.ipImpl == nil {
		return false
	}
	return ip.ipImpl.is6()
}

// Unmap returns ip with any IPv4-mapped IPv6 address prefix removed.
//
// That is, if ip is an IPv6 address wrapping an IPv4 adddress, it
// returns the wrapped IPv4 address. Otherwise it returns ip, regardless
// of its type.
func (ip IP) Unmap() IP {
	if !ip.Is4in6() {
		return ip
	}
	a := ip.ipImpl.as16()
	return IP{v4Addr{a[12], a[13], a[14], a[15]}}
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

// String returns the string form of the IP address ip.
// It returns one of 4 forms:
//
//   - "invalid IP", if ip is the zero value
//   - IPv4 dotted decimal ("192.0.2.1")
//   - IPv6 ("2001:db8::1")
//   - IPv6 with zone ("fe80:db8::1%eth0")
//
// Note that unlike the Go standard library's IP.String method,
// IP4-mapped IPv6 addresses do not format as dotted decimals.
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

// IPPort is an IP & port number.
//
// It's meant to be used as a value type.
type IPPort struct {
	IP   IP
	Port uint16
}

// UDPAddr returns a standard library net.UDPAddr from p.
// The returned value is always non-nil. If p.IP is the zero
// value, then UDPAddr.IP is nil.
func (p IPPort) UDPAddr() *net.UDPAddr {
	ip, zone := p.IP.ipZone()
	return &net.UDPAddr{
		IP:   ip,
		Port: int(p.Port),
		Zone: zone,
	}
}

// TCPAddr returns a standard library net.UDPAddr from p.
// The returned value is always non-nil. If p.IP is the zero
// value, then TCPAddr.IP is nil.
func (p IPPort) TCPAddr() *net.TCPAddr {
	ip, zone := p.IP.ipZone()
	return &net.TCPAddr{
		IP:   ip,
		Port: int(p.Port),
		Zone: zone,
	}
}
