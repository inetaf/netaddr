// Copyright 2020 The Inet.Af AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package netaddr contains a IP address type that's in many ways
// better than the Go standard library's net.IP type. Building on that
// IP type, the package also contains IPPrefix, IPPort, IPRange, and
// IPSet types.
//
// Notably, this package's IP type takes less memory, is immutable,
// comparable (supports == and being a map key), and more. See
// https://github.com/inetaf/netaddr for background.
package netaddr // import "inet.af/netaddr"

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"

	"go4.org/intern"
)

// copied to avoid importing math.
const maxUint16 = 1<<16 - 1

// Sizes: (64-bit)
//   net.IP:     24 byte slice header + {4, 16} = 28 to 40 bytes
//   net.IPAddr: 40 byte slice header + {4, 16} = 44 to 56 bytes + zone length
//   netaddr.IP: 24 bytes (zone is per-name singleton, shared across all users)

// IP represents an IPv4 or IPv6 address (with or without a scoped
// addressing zone), similar to Go's net.IP or net.IPAddr.
//
// Unlike net.IP or net.IPAddr, the netaddr.IP is a comparable value
// type (it supports == and can be a map key) and is immutable.
// Its memory representation is 24 bytes on 64-bit machines (the same
// size as a Go slice header) for both IPv4 and IPv6 address.
type IP struct {
	// hi and lo are the bits of an IPv6 address. If z==z4, hi and lo
	// contain the IPv4-mapped IPv6 address.
	//
	// hi and lo are constructed by interpreting a 16-byte IPv6
	// address as a big-endian 128-bit number. The most significant
	// bits of that number go into hi, the rest into lo.
	//
	// For example, 0011:2233:4455:6677:8899:aabb:ccdd:eeff is stored as:
	//  hi = 0x0011223344556677
	//  lo = 0x8899aabbccddeeff
	//
	// We store IPs like this, rather than as [16]byte, because it
	// turns most operations on IPs into arithmetic and bit-twiddling
	// operations on 64-bit registers, which is much faster than
	// bytewise processing.
	hi, lo uint64

	// z is a combination of the address family and the IPv6 zone.
	//
	// nil means invalid IP address (for the IP zero value).
	// z4 means an IPv4 address.
	// z6noz means an IPv6 address without a zone.
	//
	// Otherwise it's the interned zone name string.
	z *intern.Value
}

// z0, z4, and z6noz are sentinel IP.z values.
// See the IP type's field docs.
var (
	z0    = (*intern.Value)(nil)
	z4    = new(intern.Value)
	z6noz = new(intern.Value)
)

// IPv6LinkLocalAllNodes returns the IPv6 link-local all nodes multicast
// address ff02::1.
func IPv6LinkLocalAllNodes() IP { return IPv6Raw([16]byte{0: 0xff, 1: 0x02, 15: 0x01}) }

// IPv6Unspecified returns the IPv6 unspecified address ::.
func IPv6Unspecified() IP { return IP{z: z6noz} }

// IPv4 returns the IP of the IPv4 address a.b.c.d.
func IPv4(a, b, c, d uint8) IP {
	return IP{
		lo: 0xffff00000000 | uint64(a)<<24 | uint64(b)<<16 | uint64(c)<<8 | uint64(d),
		z:  z4,
	}
}

// IPv6Raw returns the IPv6 address given by the bytes in addr,
// without an implicit Unmap call to unmap any v6-mapped IPv4
// address.
func IPv6Raw(addr [16]byte) IP {
	return IP{
		hi: binary.BigEndian.Uint64(addr[:8]),
		lo: binary.BigEndian.Uint64(addr[8:]),
		z:  z6noz,
	}
}

// ipv6Slice is like IPv6Raw, but operates on a 16-byte slice. Assumes
// slice is 16 bytes, caller must enforce this.
func ipv6Slice(addr []byte) IP {
	return IP{
		hi: binary.BigEndian.Uint64(addr[:8]),
		lo: binary.BigEndian.Uint64(addr[8:]),
		z:  z6noz,
	}
}

// IPFrom16 returns the IP address given by the bytes in addr,
// unmapping any v6-mapped IPv4 address.
//
// It is equivalent to calling IPv6Raw(addr).Unmap().
func IPFrom16(addr [16]byte) IP {
	return IPv6Raw(addr).Unmap()
}

// ParseIP parses s as an IP address, returning the result. The string
// s can be in dotted decimal ("192.0.2.1"), IPv6 ("2001:db8::68"),
// or IPv6 with a scoped addressing zone ("fe80::1cc0:3e8c:119f:c2e1%ens18").
func ParseIP(s string) (IP, error) {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '.':
			return parseIPv4(s)
		case ':':
			return parseIPv6(s)
		case '%':
			// Assume that this was trying to be an IPv6 address with
			// a zone specifier, but the address is missing.
			return IP{}, parseIPErrorf(s, "missing IPv6 address")
		}
	}
	return IP{}, errors.New("unable to parse IP")
}

// MustParseIP calls ParseIP(s) and panics on error.
// It is intended for use in tests with hard-coded strings.
func MustParseIP(s string) IP {
	ip, err := ParseIP(s)
	if err != nil {
		panic(err)
	}
	return ip
}

func parseIPErrorf(ip, msg string, args ...interface{}) error {
	msg = "ParseIP(%q): " + msg
	args = append([]interface{}{ip}, args...)
	return fmt.Errorf(msg, args...)
}

// parseIPv4 parses s as an IPv4 address (in form "192.168.0.1").
func parseIPv4(s string) (ip IP, err error) {
	var ip4 [4]byte

	for i := 0; i < 4; i++ {
		var (
			j   int
			acc uint16
		)
		// Parse one byte of digits. Bail if we overflow, stop at
		// first non-digit.
		//
		// As of Go 1.15, don't try to factor this digit reading into
		// a helper function. Its complexity is slightly too high for
		// inlining, which ends up costing +50% in parse time.
		for j = 0; j < len(s); j++ {
			if s[j] < '0' || s[j] > '9' {
				break
			}
			acc = (acc * 10) + uint16(s[j]-'0')
			if acc > 255 {
				return IP{}, parseIPErrorf(s, "IPv4 field has value >255")
			}
		}
		// There must be at least 1 digit per quad.
		if j == 0 {
			return IP{}, parseIPErrorf(s, "each dot-separated field must have at least one digit")
		}

		ip4[i] = uint8(acc)

		// Non-final byte must be followed by a dot
		if i < 3 {
			if len(s) == j {
				return IP{}, parseIPErrorf(s, "address too short")
			} else if s[j] != '.' {
				return IP{}, parseIPErrorf(s, "unexpected character %q", s[j])
			}
			j++
		}

		// Advance to the next set of digits.
		s = s[j:]
	}
	if len(s) != 0 {
		if s[0] == '%' {
			return IP{}, parseIPErrorf(s, "zone specifier not allowed with IPv4 addresses")
		}
		return IP{}, parseIPErrorf(s, "trailing garbage after address")
	}

	return IPv4(ip4[0], ip4[1], ip4[2], ip4[3]), nil
}

// parseIPv6 parses s as an IPv6 address (in form "2001:db8::68").
func parseIPv6(s string) (IP, error) {
	// Split off the zone right from the start. Yes it's a second scan
	// of the string, but trying to handle it inline makes a bunch of
	// other inner loop conditionals more expensive, and it ends up
	// being slower.
	zone := ""
	i := strings.IndexByte(s, '%')
	if i != -1 {
		s, zone = s[:i], s[i+1:]
		if zone == "" {
			// Not allowed to have an empty zone if explicitly specified.
			return IP{}, parseIPErrorf(s, "zone must be a non-empty string")
		}
	}

	var ip [16]byte
	ellipsis := -1 // position of ellipsis in ip

	// Might have leading ellipsis
	if len(s) >= 2 && s[0] == ':' && s[1] == ':' {
		ellipsis = 0
		s = s[2:]
		// Might be only ellipsis
		if len(s) == 0 {
			return IPv6Unspecified().WithZone(zone), nil
		}
	}

	// Loop, parsing hex numbers followed by colon.
	i = 0
	for i < 16 {
		// Hex number. Similar to parseIPv4, inlining the hex number
		// parsing yields a significant performance increase.
		off := 0
		acc := uint32(0)
		for ; off < len(s); off++ {
			c := s[off]
			if c >= '0' && c <= '9' {
				acc = (acc << 4) + uint32(c-'0')
			} else if c >= 'a' && c <= 'f' {
				acc = (acc << 4) + uint32(c-'a'+10)
			} else if c >= 'A' && c <= 'F' {
				acc = (acc << 4) + uint32(c-'A'+10)
			} else {
				break
			}
			if acc > maxUint16 {
				// Overflow, fail.
				return IP{}, parseIPErrorf(s, "IPv6 field has value >=2^16")
			}
		}
		if off == 0 {
			// No digits found, fail.
			return IP{}, parseIPErrorf(s, "each colon-separated field must have at least one digit")
		}

		// If followed by dot, might be in trailing IPv4.
		if off < len(s) && s[off] == '.' {
			if ellipsis < 0 && i != 12 {
				// Not the right place.
				return IP{}, parseIPErrorf(s, "embedded IPv4 address must replace the final 2 fields of the address")
			}
			if i+4 > 16 {
				// Not enough room.
				return IP{}, parseIPErrorf(s, "too many hex fields to fit an embedded IPv4 at the end of the address")
			}
			// TODO: could make this a bit faster by having a helper
			// that parses to a [4]byte, and have both parseIPv4 and
			// parseIPv6 use it.
			ip4, err := parseIPv4(s)
			if err != nil {
				return IP{}, parseIPErrorf(s, "parsing embedded IPv4: %w", err)
			}
			ip[i] = ip4.v4(0)
			ip[i+1] = ip4.v4(1)
			ip[i+2] = ip4.v4(2)
			ip[i+3] = ip4.v4(3)
			s = ""
			i += 4
			break
		}

		// Save this 16-bit chunk.
		ip[i] = byte(acc >> 8)
		ip[i+1] = byte(acc)
		i += 2

		// Stop at end of string.
		s = s[off:]
		if len(s) == 0 {
			break
		}

		// Otherwise must be followed by colon and more.
		if s[0] != ':' {
			return IP{}, parseIPErrorf(s, "unexpected character %q when colon expected", s[0])
		} else if len(s) == 1 {
			return IP{}, parseIPErrorf(s, "colon must be followed by more characters")
		}
		s = s[1:]

		// Look for ellipsis.
		if s[0] == ':' {
			if ellipsis >= 0 { // already have one
				return IP{}, parseIPErrorf(s, "multiple :: in address")
			}
			ellipsis = i
			s = s[1:]
			if len(s) == 0 { // can be at end
				break
			}
		}
	}

	// Must have used entire string.
	if len(s) != 0 {
		return IP{}, parseIPErrorf(s, "trailing garbage after address")
	}

	// If didn't parse enough, expand ellipsis.
	if i < 16 {
		if ellipsis < 0 {
			return IP{}, parseIPErrorf(s, "address string too short")
		}
		n := 16 - i
		for j := i - 1; j >= ellipsis; j-- {
			ip[j+n] = ip[j]
		}
		for j := ellipsis + n - 1; j >= ellipsis; j-- {
			ip[j] = 0
		}
	} else if ellipsis >= 0 {
		// Ellipsis must represent at least one 0 group.
		return IP{}, parseIPErrorf(s, "the :: must expand to at least one field of zeros")
	}
	return IPv6Raw(ip).WithZone(zone), nil
}

// FromStdIP returns an IP from the standard library's IP type.
//
// If std is invalid, ok is false.
//
// FromStdIP implicitly unmaps IPv6-mapped IPv4 addresses. That is, if
// len(std) == 16 and contains an IPv4 address, only the IPv4 part is
// returned, without the IPv6 wrapper. This is the common form returned by
// the standard library's ParseIP: https://play.golang.org/p/qdjylUkKWxl.
// To convert a standard library IP without the implicit unmapping, use
// FromStdIPRaw.
func FromStdIP(std net.IP) (ip IP, ok bool) {
	ret, ok := FromStdIPRaw(std)
	if ret.Is4in6() {
		ret.z = z4
	}
	return ret, ok
}

// FromStdIPRaw returns an IP from the standard library's IP type.
// If std is invalid, ok is false.
// Unlike FromStdIP, FromStdIPRaw does not do an implicit Unmap if
// len(std) == 16 and contains an IPv6-mapped IPv4 address.
func FromStdIPRaw(std net.IP) (ip IP, ok bool) {
	switch len(std) {
	case 4:
		return IPv4(std[0], std[1], std[2], std[3]), true
	case 16:
		return ipv6Slice(std), true
	}
	return IP{}, false
}

// v4 returns the i'th byte of ip. If ip is not an IPv4, v4 returns
// unspecified garbage.
func (ip IP) v4(i uint8) uint8 {
	return uint8(ip.lo >> ((3 - i) * 8))
}

// v6 returns the i'th byte of ip. If ip is an IPv4 address, this
// accesses the IPv4-mapped IPv6 address form of the IP.
func (ip IP) v6(i uint8) uint8 {
	if i >= 8 {
		return uint8(ip.lo >> ((15 - i) * 8))
	} else {
		return uint8(ip.hi >> ((7 - i) * 8))
	}
}

// IsZero reports whether ip is the zero value of the IP type.
// The zero value is not a valid IP address of any type.
//
// Note that "0.0.0.0" and "::" are not the zero value.
func (ip IP) IsZero() bool { return ip == IP{} }

// BitLen returns the number of bits in the IP address:
// 32 for IPv4 or 128 for IPv6.
// For the zero value (see IP.IsZero), it returns 0.
// For IP4-mapped IPv6 addresses, it returns 128.
func (ip IP) BitLen() uint8 {
	switch ip.z {
	case z0:
		return 0
	case z4:
		return 32
	}
	return 128
}

// Zone returns ip's IPv6 scoped addressing zone, if any.
func (ip IP) Zone() string {
	if ip.z == nil {
		return ""
	}
	zone, _ := ip.z.Get().(string)
	return zone
}

// Compare returns an integer comparing two IPs.
// The result will be 0 if ip==ip2, -1 if ip < ip2, and +1 if ip > ip2.
// The definition of "less than" is the same as the IP.Less method.
func (ip IP) Compare(ip2 IP) int {
	f1, f2 := ip.BitLen(), ip2.BitLen()
	if f1 < f2 {
		return -1
	}
	if f1 > f2 {
		return 1
	}
	if ip.hi < ip2.hi {
		return -1
	}
	if ip.hi > ip2.hi {
		return 1
	}
	if ip.lo < ip2.lo {
		return -1
	}
	if ip.lo > ip2.lo {
		return 1
	}
	if ip.Is6() {
		za, zb := ip.Zone(), ip2.Zone()
		if za < zb {
			return -1
		} else if za > zb {
			return 1
		}
	}
	return 0
}

// Less reports whether ip sorts before ip2.
// IP addresses sort first by length, then their address.
// IPv6 addresses with zones sort just after the same address without a zone.
func (ip IP) Less(ip2 IP) bool { return ip.Compare(ip2) == -1 }

// ipZone returns the standard library net.IP from ip, as well
// as the zone.
// The optional reuse IP provides memory to reuse.
func (ip IP) ipZone(reuse net.IP) (stdIP net.IP, zone string) {
	base := reuse[:0]
	switch {
	case ip.z == z0:
		return nil, ""
	case ip.Is4():
		a4 := ip.As4()
		return append(base, a4[:]...), ""
	default:
		a16 := ip.As16()
		return append(base, a16[:]...), ip.Zone()
	}
}

// IPAddr returns the net.IPAddr representation of an IP. The returned value is
// always non-nil, but the IPAddr.IP will be nil if ip is the zero value.
// If ip contains a zone identifier, IPAddr.Zone is populated.
func (ip IP) IPAddr() *net.IPAddr {
	stdIP, zone := ip.ipZone(nil)
	return &net.IPAddr{IP: stdIP, Zone: zone}
}

// Is4 reports whether ip is an IPv4 address.
//
// It returns false for IP4-mapped IPv6 addresses. See IP.Unmap.
func (ip IP) Is4() bool {
	return ip.z == z4
}

// Is4in6 reports whether ip is an IPv4-mapped IPv6 address.
func (ip IP) Is4in6() bool {
	return ip.Is6() && ip.hi == 0 && ip.lo>>32 == 0xffff
}

// Is6 reports whether ip is an IPv6 address, including IPv4-mapped
// IPv6 addresses.
func (ip IP) Is6() bool {
	return ip.z != z0 && ip.z != z4
}

// Unmap returns ip with any IPv4-mapped IPv6 address prefix removed.
//
// That is, if ip is an IPv6 address wrapping an IPv4 adddress, it
// returns the wrapped IPv4 address. Otherwise it returns ip, regardless
// of its type.
func (ip IP) Unmap() IP {
	if ip.Is4in6() {
		ip.z = z4
	}
	return ip
}

// WithZone returns an IP that's the same as ip but with the provided
// zone. If zone is empty, the zone is removed. If ip is an IPv4
// address it's returned unchanged.
func (ip IP) WithZone(zone string) IP {
	if !ip.Is6() {
		return ip
	}
	if zone == "" {
		ip.z = z6noz
		return ip
	}
	ip.z = intern.Get(zone)
	return ip
}

// IsLinkLocalUnicast reports whether ip is a link-local unicast address.
// If ip is the zero value, it will return false.
func (ip IP) IsLinkLocalUnicast() bool {
	if ip.Is4() {
		return ip.v4(0) == 169 && ip.v4(1) == 254
	}
	if ip.Is6() {
		return ip.v6(0) == 0xfe && ip.v6(1) == 0x80
	}
	return false // zero value
}

// IsLoopback reports whether ip is a loopback address. If ip is the zero value,
// it will return false.
func (ip IP) IsLoopback() bool {
	if ip.Is4() {
		return ip.v4(0) == 127
	}
	if ip.Is6() {
		return ip.hi == 0 && ip.lo == 1
	}
	return false // zero value
}

// IsMulticast reports whether ip is a multicast address. If ip is the zero
// value, it will return false.
func (ip IP) IsMulticast() bool {
	if ip.Is4() {
		return ip.v4(0)&0xf0 == 0xe0
	}
	if ip.Is6() {
		return ip.v6(0) == 0xff
	}
	return false // zero value
}

// Prefix applies a CIDR mask of leading bits to IP, producing an IPPrefix
// of the specified length. If IP is the zero value, a zero-value IPPrefix and
// a nil error are returned. If bits is larger than 32 for an IPv4 address or
// 128 for an IPv6 address, an error is returned.
func (ip IP) Prefix(bits uint8) (IPPrefix, error) {
	effectiveBits := bits
	switch ip.z {
	case z0:
		return IPPrefix{}, nil
	case z4:
		if bits > 32 {
			return IPPrefix{}, fmt.Errorf("prefix length %d too large for IPv4", bits)
		}
		effectiveBits += 96
	default:
		if bits > 128 {
			return IPPrefix{}, fmt.Errorf("prefix length %d too large for IPv6", bits)
		}
	}
	mhi, mlo := mask6(effectiveBits)
	ip.hi &= mhi
	ip.lo &= mlo
	return IPPrefix{ip, bits}, nil
}

// As16 returns the IP address in its 16 byte representation.
// IPv4 addresses are returned in their v6-mapped form.
// IPv6 addresses with zones are returned without their zone (use the
// Zone method to get it).
// The ip zero value returns all zeroes.
func (ip IP) As16() [16]byte {
	var ret [16]byte
	binary.BigEndian.PutUint64(ret[:8], ip.hi)
	binary.BigEndian.PutUint64(ret[8:], ip.lo)
	return ret
}

// As4 returns an IPv4 or IPv4-in-IPv6 address in its 4 byte representation.
// If ip is the IP zero value or an IPv6 address, As4 panics.
// Note that 0.0.0.0 is not the zero value.
func (ip IP) As4() [4]byte {
	if ip.z == z4 || ip.Is4in6() {
		var ret [4]byte
		binary.BigEndian.PutUint32(ret[:], uint32(ip.lo))
		return ret
	}
	if ip.z == z0 {
		panic("As4 called on IP zero value")
	}
	panic("As4 called on IPv6 address")
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
	if ip.z == z0 {
		return "invalid IP"
	}
	if ip.Is4() {
		return fmt.Sprintf("%d.%d.%d.%d", ip.v4(0), ip.v4(1), ip.v4(2), ip.v4(3))
	}
	if ip.Is4in6() {
		zone := ip.Zone()
		var percent string
		if zone != "" {
			percent = "%"
		}
		return fmt.Sprintf("::ffff:%x:%x%s%s", uint16(ip.v4(0))<<8|uint16(ip.v4(1)), uint16(ip.v4(2))<<8|uint16(ip.v4(3)), percent, zone)
	}
	a16 := ip.As16()
	return (&net.IPAddr{IP: net.IP(a16[:]), Zone: ip.Zone()}).String()
}

// MarshalText implements the encoding.TextMarshaler interface,
// The encoding is the same as returned by String, with one exception:
// If ip is the zero value, the encoding is the empty string.
func (ip IP) MarshalText() ([]byte, error) {
	if ip.z == z0 {
		return []byte(""), nil
	}
	return []byte(ip.String()), nil
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
// The IP address is expected in a form accepted by ParseIP.
// It returns an error if *ip is not the IP zero value.
func (ip *IP) UnmarshalText(text []byte) error {
	if ip.z != z0 {
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

// ParseIPPort parses s as an IPPort.
//
// It doesn't do any name resolution, and ports must be numeric.
func ParseIPPort(s string) (IPPort, error) {
	var ipp IPPort
	ip, port, err := net.SplitHostPort(s)
	if err != nil {
		return ipp, err
	}
	port16, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return ipp, fmt.Errorf("invalid port %q parsing %q", port, s)
	}
	ipp.Port = uint16(port16)
	ipp.IP, err = ParseIP(ip)
	if err != nil {
		return IPPort{}, err
	}
	return ipp, nil
}

// MustParseIPPort calls ParseIPPort(s) and panics on error.
// It is intended for use in tests with hard-coded strings.
func MustParseIPPort(s string) IPPort {
	ip, err := ParseIPPort(s)
	if err != nil {
		panic(err)
	}
	return ip
}

// IsZero reports whether p is its zero value.
func (p IPPort) IsZero() bool { return p == IPPort{} }

func (p IPPort) String() string {
	if p.IP.z == z4 {
		a := p.IP.As4()
		return fmt.Sprintf("%d.%d.%d.%d:%d", a[0], a[1], a[2], a[3], p.Port)
	}
	// TODO: this could be more efficient allocation-wise:
	return net.JoinHostPort(p.IP.String(), strconv.Itoa(int(p.Port)))
}

// MarshalText implements the encoding.TextMarshaler interface. The
// encoding is the same as returned by String, with one exception: if
// p.IP is the zero value, the encoding is the empty string.
func (p IPPort) MarshalText() ([]byte, error) {
	if p.IP.z == z0 {
		return []byte(""), nil
	}
	return []byte(p.String()), nil
}

// UnmarshalText implements the encoding.TextUnmarshaler
// interface. The IPPort is expected in a form accepted by
// ParseIPPort. It returns an error if *p is not the IPPort zero
// value.
func (p *IPPort) UnmarshalText(text []byte) error {
	if p.IP.z != z0 || p.Port != 0 {
		return errors.New("netaddr: refusing to UnmarshalText into non-zero IP")
	}
	if len(text) == 0 {
		return nil
	}
	var err error
	*p, err = ParseIPPort(string(text))
	return err
}

// FromStdAddr maps the components of a standard library TCPAddr or
// UDPAddr into an IPPort.
func FromStdAddr(stdIP net.IP, port int, zone string) (_ IPPort, ok bool) {
	ip, ok := FromStdIP(stdIP)
	if !ok || port < 0 || port > maxUint16 {
		return
	}
	ip = ip.Unmap()
	if zone != "" {
		if ip.Is4() {
			ok = false
			return
		}
		ip = ip.WithZone(zone)
	}
	return IPPort{IP: ip, Port: uint16(port)}, true
}

var udpAddrPool = &sync.Pool{
	New: func() interface{} { return new(net.UDPAddr) },
}

// UDPAddr returns a standard library net.UDPAddr from p.
// The returned value is always non-nil. If p.IP is the zero
// value, then UDPAddr.IP is nil.
//
// UDPAddr necessarily does two allocations. If you call PutUDPAddr
// after you're done with it, though, then subsequent UDPAddr calls
// can reuse the memory.
func (p IPPort) UDPAddr() *net.UDPAddr {
	ua := udpAddrPool.Get().(*net.UDPAddr)
	ua.Port = int(p.Port)
	ua.IP, ua.Zone = p.IP.ipZone(ua.IP)
	return ua
}

// PutUDPAddr adds ua to an internal pool for later reuse by IPPort.UDPAddr.
// Use of PutUDPAddr is optional; improper use can cause mysterious errors.
// You must only call PutUDPAddr if there are no remaining references to ua.
func PutUDPAddr(ua *net.UDPAddr) { udpAddrPool.Put(ua) }

// TCPAddr returns a standard library net.UDPAddr from p.
// The returned value is always non-nil. If p.IP is the zero
// value, then TCPAddr.IP is nil.
func (p IPPort) TCPAddr() *net.TCPAddr {
	ip, zone := p.IP.ipZone(nil)
	return &net.TCPAddr{
		IP:   ip,
		Port: int(p.Port),
		Zone: zone,
	}
}

// IPPrefix is an IP address prefix (CIDR) representing an IP network.
//
// The first Bits of IP are specified, the remaining bits match any address.
// The range of Bits is [0,32] for IPv4 or [0,128] for IPv6.
type IPPrefix struct {
	IP   IP
	Bits uint8
}

// IsZero reports whether p is its zero value.
func (p IPPrefix) IsZero() bool { return p == IPPrefix{} }

// IsSingleIP reports whether p contains exactly one IP.
func (p IPPrefix) IsSingleIP() bool { return p.Bits != 0 && p.Bits == p.IP.BitLen() }

// FromStdIPNet returns an IPPrefix from the standard library's IPNet type.
// If std is invalid, ok is false.
func FromStdIPNet(std *net.IPNet) (prefix IPPrefix, ok bool) {
	ip, ok := FromStdIP(std.IP)
	if !ok {
		return IPPrefix{}, false
	}

	if l := len(std.Mask); l != net.IPv4len && l != net.IPv6len {
		// Invalid mask.
		return IPPrefix{}, false
	}

	ones, bits := std.Mask.Size()
	if ones == 0 && bits == 0 {
		// IPPrefix does not support non-contiguous masks.
		return IPPrefix{}, false
	}

	return IPPrefix{
		IP:   ip,
		Bits: uint8(ones),
	}, true
}

// ParseIPPrefix parses s as an IP address prefix.
// The string can be in the form "192.168.1.0/24" or "2001::db8::/32",
// the CIDR notation defined in RFC 4632 and RFC 4291.
//
// Note that masked address bits are not zeroed. Use Masked for that.
func ParseIPPrefix(s string) (IPPrefix, error) {
	i := strings.IndexByte(s, '/')
	if i < 0 {
		return IPPrefix{}, fmt.Errorf("netaddr.ParseIPPrefix(%q): no '/'", s)
	}
	ip, err := ParseIP(s[:i])
	if err != nil {
		return IPPrefix{}, fmt.Errorf("netaddr.ParseIPPrefix(%q): %v", s, err)
	}
	s = s[i+1:]
	bits, err := strconv.Atoi(s)
	if err != nil {
		return IPPrefix{}, fmt.Errorf("netaddr.ParseIPPrefix(%q): bad prefix: %v", s, err)
	}
	maxBits := 32
	if ip.Is6() {
		maxBits = 128
	}
	if bits < 0 || bits > maxBits {
		return IPPrefix{}, fmt.Errorf("netaddr.ParseIPPrefix(%q): prefix length out of range", s)
	}
	return IPPrefix{
		IP:   ip,
		Bits: uint8(bits),
	}, nil
}

// MustParseIPPrefix calls ParseIPPrefix(s) and panics on error.
// It is intended for use in tests with hard-coded strings.
func MustParseIPPrefix(s string) IPPrefix {
	ip, err := ParseIPPrefix(s)
	if err != nil {
		panic(err)
	}
	return ip
}

// Masked returns p in its canonical form, with bits of p.IP not in p.Bits masked off.
// If p is zero or otherwise invalid, Masked returns the zero value.
func (p IPPrefix) Masked() IPPrefix {
	if m, err := p.IP.Prefix(p.Bits); err == nil {
		return m
	}
	return IPPrefix{}
}

// Range returns the inclusive range of IPs that p covers.
//
// If p is zero or otherwise invalid, Range returns the zero value.
func (p IPPrefix) Range() IPRange {
	p = p.Masked()
	if p.IsZero() {
		return IPRange{}
	}
	return IPRange{From: p.IP, To: p.lastIP()}
}

// IPNet returns the net.IPNet representation of an IPPrefix.
// The returned value is always non-nil.
// Any zone identifier is dropped in the conversion.
func (p IPPrefix) IPNet() *net.IPNet {
	bits := 128
	if p.IP.Is4() {
		bits = 32
	}
	stdIP, _ := p.IP.ipZone(nil)
	return &net.IPNet{
		IP:   stdIP,
		Mask: net.CIDRMask(int(p.Bits), bits),
	}
}

// mask4 returns a bit mask that selects the topmost n bits of a
// uint32.
func mask4(n uint8) uint32 {
	return ^uint32(0) << (32 - n)
}

// mask6 returns a bit mask that selects the topmost n bits of a
// 128-bit number. Due to Go's lack of 128-bit numeric types, the mask
// is returned as a pair of uint64s, in the same order as the uint64
// pair in the IP type.
func mask6(n uint8) (hi, lo uint64) {
	if n > 64 {
		return ^uint64(0), ^uint64(0) << (128 - n)
	} else {
		return ^uint64(0) << (64 - n), 0
	}
}

// Contains reports whether the network p includes addr.
//
// An IPv4 address will not match an IPv6 prefix.
// A v6-mapped IPv6 address will not match an IPv4 prefix.
// A zero-value IP will not match any prefix.
func (p IPPrefix) Contains(addr IP) bool {
	if f1, f2 := p.IP.BitLen(), addr.BitLen(); f1 == 0 || f2 == 0 || f1 != f2 {
		return false
	}
	if addr.Is4() {
		m := mask4(p.Bits)
		return uint32(addr.lo)&m == uint32(p.IP.lo)&m
	} else {
		mhi, mlo := mask6(p.Bits)
		return addr.hi&mhi == p.IP.hi&mhi && addr.lo&mlo == p.IP.lo&mlo
	}
}

// Overlaps reports whether p and o overlap at all.
//
// If p and o are of different address families or either have a zero
// IP, it reports false. Like the Contains method, a prefix with a
// v6-mapped IPv4 IP is still treated as an IPv6 mask.
//
// If either has a Bits of zero, it returns true.
func (p IPPrefix) Overlaps(o IPPrefix) bool {
	if p.IP.IsZero() || o.IP.IsZero() {
		return false
	}
	if p == o {
		return true
	}
	if p.IP.Is4() != o.IP.Is4() {
		return false
	}
	var minBits uint8
	if p.Bits < o.Bits {
		minBits = p.Bits
	} else {
		minBits = o.Bits
	}
	if minBits == 0 {
		return true
	}
	// One of these Prefix calls might look redundant, but we don't require
	// that p and o values are normalized (via IPPrefix.Masked) first,
	// so the Prefix call on the one that's already minBits serves to zero
	// out any remaining bits in IP.
	var err error
	if p, err = p.IP.Prefix(minBits); err != nil {
		return false
	}
	if o, err = o.IP.Prefix(minBits); err != nil {
		return false
	}
	return p.IP == o.IP
}

// MarshalText implements the encoding.TextMarshaler interface,
// The encoding is the same as returned by String, with one exception:
// If p is the zero value, the encoding is the empty string.
func (p IPPrefix) MarshalText() ([]byte, error) {
	if p == (IPPrefix{}) {
		return []byte(""), nil
	}

	return []byte(p.String()), nil
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
// The IP address is expected in a form accepted by ParseIPPrefix.
// It returns an error if *p is not the IPPrefix zero value.
func (p *IPPrefix) UnmarshalText(text []byte) error {
	if *p != (IPPrefix{}) {
		return errors.New("netaddr: refusing to Unmarshal into non-zero IPPrefix")
	}

	if len(text) == 0 {
		return nil
	}

	var err error
	*p, err = ParseIPPrefix(string(text))
	return err
}

// Strings returns the CIDR notation of p: "<ip>/<bits>".
func (p IPPrefix) String() string {
	return fmt.Sprintf("%s/%d", p.IP, p.Bits)
}

// lastIP returns the last IP in the prefix.
func (p IPPrefix) lastIP() IP {
	if p.IP.IsZero() {
		return IP{}
	}
	a16 := p.IP.As16()
	var off uint8
	var bits uint8 = 128
	if p.IP.Is4() {
		off = 12
		bits = 32
	}
	for b := p.Bits; b < bits; b++ {
		byteNum, bitInByte := b/8, 7-(b%8)
		a16[off+byteNum] |= 1 << uint(bitInByte)
	}
	if p.IP.Is4() {
		return IPFrom16(a16)
	} else {
		return IPv6Raw(a16) // doesn't unmap
	}
}

// IPRange represents an inclusive range of IP addresses
// from the same address family.
//
// The From and To IPs are inclusive bounds, both included in the
// range.
//
// To be valid, the From and To values be non-zero, have matching
// address families (IPv4 vs IPv6), and From must be less than or
// equal to To. An invalid range may be ignored.
type IPRange struct {
	// From is the initial IP address in the range.
	From IP

	// To is the final IP address in the range.
	To IP
}

// ParseIPRange parses a range out of two IPs separated by a hyphen.
//
// It returns an error if the range is not valid.
func ParseIPRange(s string) (IPRange, error) {
	var r IPRange
	h := strings.IndexByte(s, '-')
	if h == -1 {
		return r, fmt.Errorf("no hyphen in range %q", s)
	}
	from, to := s[:h], s[h+1:]
	var err error
	r.From, err = ParseIP(from)
	if err != nil {
		return r, fmt.Errorf("invalid From IP %q in range %q", from, s)
	}
	r.To, err = ParseIP(to)
	if err != nil {
		return r, fmt.Errorf("invalid To IP %q in range %q", to, s)
	}
	if !r.Valid() {
		return r, fmt.Errorf("range %v to %v not valid", r.From, r.To)
	}
	return r, nil
}

// String returns a string representation of the range.
//
// For a valid range, the form is "From-To" with a single hyphen
// separating the IPs, the same format recognized by
// ParseIPRange.
func (r IPRange) String() string {
	if r.Valid() {
		return fmt.Sprintf("%s-%s", r.From, r.To)
	}
	if r.From.IsZero() || r.To.IsZero() {
		return "zero IPRange"
	}
	return "invalid IPRange"
}

// Valid reports whether r.From and r.To are both non-zero and obey
// the documented requirements: address families match, and From is
// less than or equal to To.
func (r IPRange) Valid() bool {
	return !r.From.IsZero() && !r.To.IsZero() &&
		r.From.Is4() == r.To.Is4() &&
		!r.To.Less(r.From)
}

// Contains reports whether the range r includes addr.
//
// An invalid range always reports false.
func (r IPRange) Contains(addr IP) bool {
	return r.Valid() &&
		r.From.Compare(addr) <= 0 &&
		r.To.Compare(addr) >= 0
}

// Overlaps reports whether p and o overlap at all.
//
// If p and o are of different address families or either are invalid,
// it reports false.
func (r IPRange) Overlaps(o IPRange) bool {
	return r.Valid() &&
		o.Valid() &&
		r.From.Compare(o.To) <= 0 &&
		o.From.Compare(r.To) <= 0
}

// ip16 represents a mutable IP address, either IPv4 (in IPv6-mapped
// form) or IPv6.
//
// TODO(bradfitz): ditch this type now and fold into IP? Not used much.
type ip16 [16]byte

// bitSet reports whether the given bit in the address is set.
// (bit 0 is the most significant bit in ip[0]; bit 127 is last)
func (ip ip16) bitSet(bit uint8) bool {
	i, s := bit/8, 7-(bit%8)
	return ip[i]&(1<<s) != 0
}

func (ip *ip16) set(bit uint8) {
	i, s := bit/8, 7-(bit%8)
	ip[i] |= 1 << s
}

func (ip *ip16) clear(bit uint8) {
	i, s := bit/8, 7-(bit%8)
	ip[i] &^= 1 << s
}

// lastWithBitZero returns a copy of ip with the given bit
// cleared and the following all set.
func (ip ip16) lastWithBitZero(bit uint8) ip16 {
	ip.clear(bit)
	for ; bit < 128; bit++ {
		ip.set(bit)
	}
	return ip
}

// firstWithBitOne returns a copy of ip with the given bit
// set and the following all cleared.
func (ip ip16) firstWithBitOne(bit uint8) ip16 {
	ip.set(bit)
	for ; bit < 128; bit++ {
		ip.clear(bit)
	}
	return ip
}

// prefixMaker returns a address-family-corrected IPPrefix from ip16 and bits,
// where the input bits is always in the IPv6-mapped form for IPv4 addresses.
type prefixMaker func(ip16 ip16, bits uint8) IPPrefix

// Prefixes returns the set of IPPrefix entries that covers r.
//
// If either of r's bounds are invalid, in the wrong order, or if
// they're of different address families, then Prefixes returns nil.
func (r IPRange) Prefixes() []IPPrefix {
	if !r.Valid() {
		return nil
	}
	a16, b16 := ip16(r.From.As16()), ip16(r.To.As16())
	return appendRangePrefixes(nil, r.prefixMaker(), a16, b16)
}

func (r IPRange) prefixMaker() prefixMaker {
	if r.From.Is4() {
		return func(ip16 ip16, bits uint8) IPPrefix {
			return IPPrefix{IPFrom16([16]byte(ip16)), bits - 12*8}
		}
	}
	return func(ip16 ip16, bits uint8) IPPrefix {
		return IPPrefix{IPv6Raw([16]byte(ip16)), bits}
	}
}

func comparePrefixes(a16, b16 ip16) (common uint8, aAllZero, bAllSet bool) {
	for common < 128 && a16.bitSet(common) == b16.bitSet(common) {
		common++
	}
	// See whether a16 and b16, after their common shared bits, end
	// in all zero bits or all one bits, respectively.
	aAllZero, bAllSet = true, true
	for i := common; i < 128; i++ {
		if a16.bitSet(i) {
			aAllZero = false
			break
		}
	}
	for i := common; i < 128; i++ {
		if !b16.bitSet(i) {
			bAllSet = false
			break
		}
	}
	return
}

// Prefix returns r as an IPPrefix, if it can be presented exactly as such.
// If r is not valid or is not exactly equal to one prefix, ok is false.
func (r IPRange) Prefix() (p IPPrefix, ok bool) {
	if !r.Valid() {
		return
	}
	a16, b16 := ip16(r.From.As16()), ip16(r.To.As16())
	if common, aAllZero, bAllSet := comparePrefixes(a16, b16); aAllZero && bAllSet {
		return r.prefixMaker()(a16, common), true
	}
	return
}

func appendRangePrefixes(dst []IPPrefix, makePrefix prefixMaker, a16, b16 ip16) []IPPrefix {
	common, aAllZero, bAllSet := comparePrefixes(a16, b16)
	if aAllZero && bAllSet {
		// a16 to b16 represents a whole range, like 10.50.0.0/16.
		// (a16 being 10.50.0.0 and b16 being 10.50.255.255)
		return append(dst, makePrefix(a16, common))
	}
	// Otherwise recursively do both halves.
	dst = appendRangePrefixes(dst, makePrefix, a16, a16.lastWithBitZero(common+1))
	dst = appendRangePrefixes(dst, makePrefix, b16.firstWithBitOne(common+1), b16)
	return dst
}

func addOne(a []byte, i int) bool {
	if v := a[i]; v < 0xff {
		a[i]++
		return true
	}
	if i == 0 {
		return false
	}
	a[i] = 0
	return addOne(a, i-1)
}

func subOne(a []byte, i int) bool {
	if v := a[i]; v > 0 {
		a[i]--
		return true
	}
	if i == 0 {
		return false
	}
	a[i] = 0xff
	return subOne(a, i-1)
}

// ipFrom16Match returns an IP address from a with address family
// matching ip.
func ipFrom16Match(ip IP, a [16]byte) IP {
	if ip.Is6() {
		return IPv6Raw(a) // doesn't unwrap
	}
	return IPFrom16(a)
}

func (ip IP) withInternedZone(z *intern.Value) IP {
	ip.z = z
	return ip
}

// Next returns the IP following ip.
// If there is none, it returns the IP zero value.
func (ip IP) Next() IP {
	var ok bool
	a := ip.As16()
	if ip.Is4() {
		ok = addOne(a[12:], 3)
	} else {
		ok = addOne(a[:], 15)
	}
	if ok {
		return ipFrom16Match(ip, a).withInternedZone(ip.z)
	}
	return IP{}
}

// Prior returns the IP before ip.
// If there is none, it returns the IP zero value.
func (ip IP) Prior() IP {
	var ok bool
	a := ip.As16()
	if ip.Is4() {
		ok = subOne(a[12:], 3)
	} else {
		ok = subOne(a[:], 15)
	}
	if ok {
		return ipFrom16Match(ip, a).withInternedZone(ip.z)
	}
	return IP{}
}

// IPSet represents a set of IP addresses.
//
// The zero value is a valid value representing a set of no IPs.
//
// The Add and Remove methods add or remove IPs to/from the set.
// Add methods should be called first, as a remove operation does
// nothing on an empty set. Ranges may be fully, partially, or not
// overlapping.
type IPSet struct {
	// in are the ranges in the set.
	in []IPRange

	// out are the ranges to be removed from 'in'.
	out []IPRange
}

// Add adds ip to the set s.
func (s *IPSet) Add(ip IP) { s.AddRange(IPRange{ip, ip}) }

// AddPrefix adds p's range to s.
func (s *IPSet) AddPrefix(p IPPrefix) { s.AddRange(p.Range()) }

// AddRange adds r to s.
func (s *IPSet) AddRange(r IPRange) {
	if !r.Valid() {
		return
	}
	// If there are any removals (s.out), then we need to compact the set
	// first to get the order right.
	if len(s.out) > 0 {
		s.in = s.Ranges()
		s.out = nil
	}
	s.in = append(s.in, r)
}

// Remove removes ip from the set s.
func (s *IPSet) Remove(ip IP) { s.RemoveRange(IPRange{ip, ip}) }

// RemovePrefix removes p's range from s.
func (s *IPSet) RemovePrefix(p IPPrefix) { s.RemoveRange(p.Range()) }

// RemoveRange removes r from s.
func (s *IPSet) RemoveRange(r IPRange) {
	if r.Valid() {
		s.out = append(s.out, r)
	}
}

// AddSet adds all ranges in b to s.
func (s *IPSet) AddSet(b *IPSet) {
	for _, r := range b.Ranges() {
		s.AddRange(r)
	}
}

// RemoveSet removes all ranges in b from s.
func (s *IPSet) RemoveSet(b *IPSet) {
	for _, r := range b.Ranges() {
		s.RemoveRange(r)
	}
}

// point is either the start or end of IP range of wanted or unwanted
// IPs.
type point struct {
	ip    IP
	want  bool // true for 'add', false for remove
	start bool // true for start of range, false for (inclusive) end
}

// Less sorts points by the needs of the IPSet.Ranges function.
// See also comments in netaddr_test.go's TestPointLess.
func (a point) Less(b point) bool {
	cmp := a.ip.Compare(b.ip)
	if cmp != 0 {
		return cmp < 0
	}
	if a.want != b.want {
		if a.start == b.start {
			return !a.want
		}
		return a.start
	}
	if a.start != b.start {
		return a.start
	}
	return false
}

func discardf(format string, args ...interface{}) {}

// debugf is reassigned by tests.
var debugf = discardf

func debugLogPoints(points []point) {
	for _, p := range points {
		emo := "✅"
		if !p.want {
			emo = "❌"
		}
		if p.start {
			debugf(" {  %-15s %s\n", p.ip, emo)
		} else {
			debugf("  } %-15s %s\n", p.ip, emo)
		}
	}
}

// Ranges returns the minimum and sorted set of IP
// ranges that covers s.
func (s *IPSet) Ranges() []IPRange {
	var points []point
	for _, r := range s.in {
		points = append(points, point{r.From, true, true}, point{r.To, true, false})
	}
	for _, r := range s.out {
		points = append(points, point{r.From, false, true}, point{r.To, false, false})
	}
	sort.Slice(points, func(i, j int) bool { return points[i].Less(points[j]) })
	const debug = false
	if debug {
		debugf("post-sort:")
		debugLogPoints(points)
		debugf("merging...")
	}

	// Now build 'want', like points but with "remove" ranges removed
	// and adjacent blocks merged, and all elements alternating between
	// start and end.
	want := points[:0]
	var addDepth, removeDepth int
	for i, p := range points {
		depth := &addDepth
		if !p.want {
			depth = &removeDepth
		}
		if p.start {
			*depth++
		} else {
			*depth--
		}
		if debug {
			debugf("at[%d] (%+v), add=%v, remove=%v", i, p, addDepth, removeDepth)
		}
		if p.start && *depth != 1 {
			continue
		}
		if !p.start && *depth != 0 {
			continue
		}
		if !p.want && addDepth > 0 {
			if p.start {
				// If we're transitioning from a range of
				// addresses we want to ones we don't, insert
				// an end marker for the IP before the one we
				// don't.
				want = append(want, point{
					ip:    p.ip.Prior(),
					want:  true,
					start: false,
				})
			} else {
				want = append(want, point{
					ip:    p.ip.Next(),
					want:  true,
					start: true,
				})
			}
		}
		if !p.want || removeDepth > 0 {
			continue
		}
		// Merge adjacent ranges. Remove prior and skip this
		// start.
		if p.start && len(want) > 0 {
			prior := &want[len(want)-1]
			if !prior.start && prior.ip == p.ip.Prior() {
				want = want[:len(want)-1]
				continue
			}
		}
		want = append(want, p)
	}
	if debug {
		debugf("post-merge:")
		debugLogPoints(want)
	}

	if len(want)%2 == 1 {
		panic("internal error; odd number")
	}

	out := make([]IPRange, 0, len(want)/2)
	for i := 0; i < len(want); i += 2 {
		if !want[i].want {
			panic("internal error; non-want in range")
		}
		if !want[i].start {
			panic("internal error; odd not start")
		}
		if want[i+1].start {
			panic("internal error; even not end")
		}
		out = append(out, IPRange{
			From: want[i].ip,
			To:   want[i+1].ip,
		})
	}
	return out
}

// Prefixes returns the minimum and sorted set of IP prefixes
// that covers s.
// returning a new slice of prefixes that covers all of the given 'add'
// prefixes with all the 'remove' prefixes removed.
func (s *IPSet) Prefixes() []IPPrefix {
	var out []IPPrefix
	for _, r := range s.Ranges() {
		out = append(out, r.Prefixes()...)
	}
	return out
}

// ContainsFunc returns a func that reports whether an IP is in s.
// The returned func operates on a copy of s, so s may be mutated
// later.
func (s *IPSet) ContainsFunc() (contains func(IP) bool) {
	rv := s.Ranges()
	// TODO(bradfitz): build a faster data structure with
	// with s.Prefixes()?
	return func(ip IP) bool {
		i := sort.Search(len(rv), func(i int) bool {
			return ip.Less(rv[i].From)
		})
		if i == 0 {
			return false
		}
		i--
		if ip.Less(rv[i].From) {
			return false
		}
		if rv[i].To.Less(ip) {
			return false
		}
		return true
	}
}
