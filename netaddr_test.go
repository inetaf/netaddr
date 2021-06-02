// Copyright 2020 The Inet.Af AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//lint:file-ignore U1000 allow unused code in tests for experiments.

package netaddr

import (
	"bytes"
	"encoding"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"reflect"
	"sort"
	"strings"
	"testing"

	"go4.org/intern"
)

var long = flag.Bool("long", false, "run long tests")

func TestParseIP(t *testing.T) {
	var validIPs = []struct {
		in     string
		ip     IP          // output of ParseIP()
		ipaddr *net.IPAddr // output of .IPAddr()
		str    string      // output of String(). If "", use in.
	}{
		// Basic zero IPv4 address.
		{
			in:     "0.0.0.0",
			ip:     IP{uint128{0, 0xffff00000000}, z4},
			ipaddr: &net.IPAddr{IP: net.ParseIP("0.0.0.0")},
		},
		// Basic non-zero IPv4 address.
		{
			in:     "192.168.140.255",
			ip:     IP{uint128{0, 0xffffc0a88cff}, z4},
			ipaddr: &net.IPAddr{IP: net.ParseIP("192.168.140.255")},
		},
		// IPv4 address in windows-style "print all the digits" form.
		{
			in:     "010.000.015.001",
			ip:     IP{uint128{0, 0xffff0a000f01}, z4},
			ipaddr: &net.IPAddr{IP: net.ParseIP("10.0.15.1")},
			str:    "10.0.15.1",
		},
		// IPv4 address with a silly amount of leading zeros.
		{
			in:     "000001.00000002.00000003.000000004",
			ip:     IP{uint128{0, 0xffff01020304}, z4},
			ipaddr: &net.IPAddr{IP: net.ParseIP("1.2.3.4")},
			str:    "1.2.3.4",
		},
		// Basic zero IPv6 address.
		{
			in:     "::",
			ip:     IP{uint128{}, z6noz},
			ipaddr: &net.IPAddr{IP: net.ParseIP("::")},
		},
		// Localhost IPv6.
		{
			in:     "::1",
			ip:     IP{uint128{0, 1}, z6noz},
			ipaddr: &net.IPAddr{IP: net.ParseIP("::1")},
		},
		// Fully expanded IPv6 address.
		{
			in:     "fd7a:115c:a1e0:ab12:4843:cd96:626b:430b",
			ip:     IP{uint128{0xfd7a115ca1e0ab12, 0x4843cd96626b430b}, z6noz},
			ipaddr: &net.IPAddr{IP: net.ParseIP("fd7a:115c:a1e0:ab12:4843:cd96:626b:430b")},
		},
		// IPv6 with elided fields in the middle.
		{
			in:     "fd7a:115c::626b:430b",
			ip:     IP{uint128{0xfd7a115c00000000, 0x00000000626b430b}, z6noz},
			ipaddr: &net.IPAddr{IP: net.ParseIP("fd7a:115c::626b:430b")},
		},
		// IPv6 with elided fields at the end.
		{
			in:     "fd7a:115c:a1e0:ab12:4843:cd96::",
			ip:     IP{uint128{0xfd7a115ca1e0ab12, 0x4843cd9600000000}, z6noz},
			ipaddr: &net.IPAddr{IP: net.ParseIP("fd7a:115c:a1e0:ab12:4843:cd96::")},
		},
		// IPv6 with single elided field at the end.
		{
			in:     "fd7a:115c:a1e0:ab12:4843:cd96:626b::",
			ip:     IP{uint128{0xfd7a115ca1e0ab12, 0x4843cd96626b0000}, z6noz},
			ipaddr: &net.IPAddr{IP: net.ParseIP("fd7a:115c:a1e0:ab12:4843:cd96:626b::")},
			str:    "fd7a:115c:a1e0:ab12:4843:cd96:626b:0",
		},
		// IPv6 with single elided field in the middle.
		{
			in:     "fd7a:115c:a1e0::4843:cd96:626b:430b",
			ip:     IP{uint128{0xfd7a115ca1e00000, 0x4843cd96626b430b}, z6noz},
			ipaddr: &net.IPAddr{IP: net.ParseIP("fd7a:115c:a1e0::4843:cd96:626b:430b")},
			str:    "fd7a:115c:a1e0:0:4843:cd96:626b:430b",
		},
		// IPv6 with the trailing 32 bits written as IPv4 dotted decimal.
		{
			in:     "::ffff:192.168.140.255",
			ip:     IP{uint128{0, 0x0000ffffc0a88cff}, z6noz},
			ipaddr: &net.IPAddr{IP: net.ParseIP("::ffff:192.168.140.255")},
			str:    "::ffff:c0a8:8cff",
		},
		// IPv6 with a zone specifier.
		{
			in:     "fd7a:115c:a1e0:ab12:4843:cd96:626b:430b%eth0",
			ip:     IP{uint128{0xfd7a115ca1e0ab12, 0x4843cd96626b430b}, intern.Get("eth0")},
			ipaddr: &net.IPAddr{IP: net.ParseIP("fd7a:115c:a1e0:ab12:4843:cd96:626b:430b"), Zone: "eth0"},
		},
		// IPv6 with dotted decimal and zone specifier.
		{
			in:     "1:2::ffff:192.168.140.255%eth1",
			ip:     IP{uint128{0x0001000200000000, 0x0000ffffc0a88cff}, intern.Get("eth1")},
			ipaddr: &net.IPAddr{IP: net.ParseIP("1:2::ffff:192.168.140.255"), Zone: "eth1"},
			str:    "1:2::ffff:c0a8:8cff%eth1",
		},
		// IPv6 with capital letters.
		{
			in:     "FD9E:1A04:F01D::1",
			ip:     IP{uint128{0xfd9e1a04f01d0000, 0x1}, z6noz},
			ipaddr: &net.IPAddr{IP: net.ParseIP("FD9E:1A04:F01D::1")},
			str:    "fd9e:1a04:f01d::1",
		},
	}

	for _, test := range validIPs {
		t.Run(test.in, func(t *testing.T) {
			got, err := ParseIP(test.in)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.ip {
				t.Errorf("ParseIP(%q) got %#v, want %#v", test.in, got, test.ip)
			}

			// Check that ParseIP is a pure function.
			got2, err := ParseIP(test.in)
			if err != nil {
				t.Fatal(err)
			}
			if got != got2 {
				t.Errorf("ParseIP(%q) got 2 different results: %#v, %#v", test.in, got, got2)
			}

			// Check that ParseIP(ip.String()) is the identity function.
			s := got.String()
			got3, err := ParseIP(s)
			if err != nil {
				t.Fatal(err)
			}
			if got != got3 {
				t.Errorf("ParseIP(%q) != ParseIP(ParseIP(%q).String()). Got %#v, want %#v", test.in, test.in, got3, got)
			}

			// Check that the slow-but-readable parser produces the same result.
			slow, err := parseIPSlow(test.in)
			if err != nil {
				t.Fatal(err)
			}
			if got != slow {
				t.Errorf("ParseIP(%q) = %#v, parseIPSlow(%q) = %#v", test.in, got, test.in, slow)
			}

			// Check that IP converts to the correct stdlib value.
			std := got.IPAddr()
			std.IP = std.IP.To16() // Normalize encoding for comparison

			if !reflect.DeepEqual(std, test.ipaddr) {
				t.Errorf("ParseIP(%q).IPAddr() got %#v, want %#v", test.in, std, test.ipaddr)
			}

			// Check that the std IP converts back to the same value.
			back, ok := FromStdIP(std.IP)
			if !ok {
				t.Fatalf("FromStdIP(ParseIP(%q).IPAddr()) failed", test.in)
			}
			// FromStdIP doesn't preserve the zone, so force it back by hand.
			back.z = test.ip.z

			if back != test.ip {
				t.Errorf("FromStdIP(ParseIP(%q).IPAddr()) got %#v, want %#v", test.in, back, test.ip)
			}

			// Check that the parsed IP formats as expected.
			s = got.String()
			wants := test.str
			if wants == "" {
				wants = test.in
			}
			if s != wants {
				t.Errorf("ParseIP(%q).String() got %q, want %q", test.in, s, wants)
			}

			// Check that AppendTo matches MarshalText.
			testAppendToMarshal(t, got)

			// Check that MarshalText/UnmarshalText work similarly to
			// ParseIP/String (see TestIPMarshalUnmarshal for
			// marshal-specific behavior that's not common with
			// ParseIP/String).
			js := `"` + test.in + `"`
			var jsgot IP
			if err := json.Unmarshal([]byte(js), &jsgot); err != nil {
				t.Fatal(err)
			}
			if jsgot != got {
				t.Errorf("json.Unmarshal(%q) = %#v, want %#v", test.in, jsgot, got)
			}
			jsb, err := json.Marshal(jsgot)
			if err != nil {
				t.Fatal(err)
			}
			jswant := `"` + wants + `"`
			jsback := string(jsb)
			if jsback != jswant {
				t.Errorf("Marshal(Unmarshal(%q)) = %#v, want %#v", test.in, jsback, wants)
			}
		})
	}

	var invalidIPs = []string{
		// Empty string
		"",
		// Garbage non-IP
		"bad",
		// Single number. Some parsers accept this as an IPv4 address in
		// big-endian uint32 form, but we don't.
		"1234",
		// IPv4 with a zone specifier
		"1.2.3.4%eth0",
		// IPv4 field must have at least one digit
		".1.2.3",
		"1.2.3.",
		"1..2.3",
		// IPv4 address too long
		"1.2.3.4.5",
		// IPv4 in dotted octal form
		"0300.0250.0214.0377",
		// IPv4 in dotted hex form
		"0xc0.0xa8.0x8c.0xff",
		// IPv4 in class B form
		"192.168.12345",
		// IPv4 in class B form, with a small enough number to be
		// parseable as a regular dotted decimal field.
		"127.0.1",
		// IPv4 in class A form
		"192.1234567",
		// IPv4 in class A form, with a small enough number to be
		// parseable as a regular dotted decimal field.
		"127.1",
		// IPv4 field has value >255
		"192.168.300.1",
		// IPv4 with too many fields
		"192.168.0.1.5.6",
		// IPv6 with not enough fields
		"1:2:3:4:5:6:7",
		// IPv6 with too many fields
		"1:2:3:4:5:6:7:8:9",
		// IPv6 with 8 fields and a :: expander
		"1:2:3:4::5:6:7:8",
		// IPv6 with a field bigger than 2b
		"fe801::1",
		// IPv6 with non-hex values in field
		"fe80:tail:scal:e::",
		// IPv6 with a zone delimiter but no zone.
		"fe80::1%",
		// IPv6 (without ellipsis) with too many fields for trailing embedded IPv4.
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:192.168.140.255",
		// IPv6 (with ellipsis) with too many fields for trailing embedded IPv4.
		"ffff::ffff:ffff:ffff:ffff:ffff:ffff:192.168.140.255",
		// IPv6 with invalid embedded IPv4.
		"::ffff:192.168.140.bad",
		// IPv6 with multiple ellipsis ::.
		"fe80::1::1",
		// IPv6 with invalid non hex/colon character.
		"fe80:1?:1",
		// IPv6 with truncated bytes after single colon.
		"fe80:",
	}

	for _, s := range invalidIPs {
		t.Run(s, func(t *testing.T) {
			got, err := ParseIP(s)
			if err == nil {
				t.Errorf("ParseIP(%q) = %#v, want error", s, got)
			}

			slow, err := parseIPSlow(s)
			if err == nil {
				t.Errorf("parseIPSlow(%q) = %#v, want error", s, slow)
			}

			std := net.ParseIP(s)
			if std != nil {
				t.Errorf("net.ParseIP(%q) = %#v, want error", s, std)
			}

			if s == "" {
				// Don't test unmarshaling of "" here, do it in
				// IPMarshalUnmarshal.
				return
			}
			var jsgot IP
			js := []byte(`"` + s + `"`)
			if err := json.Unmarshal(js, &jsgot); err == nil {
				t.Errorf("json.Unmarshal(%q) = %#v, want error", s, jsgot)
			}
		})
	}
}

func TestIPv4Constructors(t *testing.T) {
	ips := []IP{
		IPv4(1, 2, 3, 4),
		IPFrom4([4]byte{1, 2, 3, 4}),
		MustParseIP("1.2.3.4"),
	}
	for i := range ips {
		for j := i + 1; j < len(ips); j++ {
			if ips[i] != ips[j] {
				t.Errorf("%v != %v", ips[i], ips[j])
			}
		}
	}
}

func TestIPMarshalUnmarshalBinary(t *testing.T) {
	tests := []struct {
		ip       string
		wantSize int
	}{
		{"", 0}, // zero IP
		{"1.2.3.4", 4},
		{"fd7a:115c:a1e0:ab12:4843:cd96:626b:430b", 16},
		{"::ffff:c000:0280", 16},
		{"::ffff:c000:0280%eth0", 20},
	}
	for _, tc := range tests {
		var ip IP
		if len(tc.ip) > 0 {
			ip = mustIP(tc.ip)
		}
		b, err := ip.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if len(b) != tc.wantSize {
			t.Fatalf("%q encoded to size %d; want %d", tc.ip, len(b), tc.wantSize)
		}
		var ip2 IP
		if err := ip2.UnmarshalBinary(b); err != nil {
			t.Fatal(err)
		}
		if ip != ip2 {
			t.Fatalf("got %v; want %v", ip2, ip)
		}
	}

	// Cannot unmarshal into a non-zero IP
	ip1 := MustParseIP("1.2.3.4")
	if err := ip1.UnmarshalBinary([]byte{1, 1, 1, 1}); err == nil {
		t.Fatal("unmarshaled into non-empty IP")
	}

	// Cannot unmarshal from unexpected IP length.
	for _, l := range []int{3, 5} {
		var ip2 IP
		if err := ip2.UnmarshalBinary(bytes.Repeat([]byte{1}, l)); err == nil {
			t.Fatalf("unmarshaled from unexpected IP length %d", l)
		}
	}
}

func TestIPMarshalUnmarshal(t *testing.T) {
	// This only tests the cases where Marshal/Unmarshal diverges from
	// the behavior of ParseIP/String. For the rest of the test cases,
	// see TestParseIP above.
	orig := `""`
	var ip IP
	if err := json.Unmarshal([]byte(orig), &ip); err != nil {
		t.Fatalf("Unmarshal(%q) got error %v", orig, err)
	}
	if !ip.IsZero() {
		t.Errorf("Unmarshal(%q) is not the zero IP", orig)
	}

	jsb, err := json.Marshal(ip)
	if err != nil {
		t.Fatalf("Marshal(%v) got error %v", ip, err)
	}
	back := string(jsb)
	if back != orig {
		t.Errorf("Marshal(Unmarshal(%q)) got %q, want %q", orig, back, orig)
	}

	// Cannot unmarshal into a non-zero IP
	ip = MustParseIP("1.2.3.4")
	if err := ip.UnmarshalText([]byte("::1")); err == nil {
		t.Fatal("unmarshaled into non-empty IP")
	}
}

func TestFromStdIP(t *testing.T) {
	tests := []struct {
		name string
		fn   func(net.IP) (IP, bool)
		std  net.IP
		want IP
	}{
		{
			name: "v4",
			fn:   FromStdIP,
			std:  []byte{1, 2, 3, 4},
			want: IPv4(1, 2, 3, 4),
		},
		{
			name: "v6",
			fn:   FromStdIP,
			std:  net.ParseIP("::1"),
			want: IPv6Raw([...]byte{15: 1}),
		},
		{
			name: "4in6-unmap",
			fn:   FromStdIP,
			std:  net.ParseIP("1.2.3.4"),
			want: IPv4(1, 2, 3, 4),
		},
		{
			name: "v4-raw",
			fn:   FromStdIPRaw,
			std:  net.ParseIP("1.2.3.4").To4(),
			want: IPv4(1, 2, 3, 4),
		},
		{
			name: "4in6-raw",
			fn:   FromStdIPRaw,
			std:  net.ParseIP("1.2.3.4"),
			want: IPv6Raw([...]byte{10: 0xff, 11: 0xff, 12: 1, 13: 2, 14: 3, 15: 4}),
		},
		{
			name: "bad-raw",
			fn:   FromStdIPRaw,
			std:  net.IP{0xff},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := tt.fn(tt.std)
			if got != tt.want {
				t.Errorf("got (%#v, %v); want %#v", got, ok, tt.want)
			}
		})
	}
}

func TestIPFrom16AndIPv6Raw(t *testing.T) {
	tests := []struct {
		name string
		fn   func([16]byte) IP
		in   [16]byte
		want IP
	}{
		{
			name: "v6-raw",
			fn:   IPv6Raw,
			in:   [...]byte{15: 1},
			want: IP{z: z6noz, addr: uint128{0, 1}},
		},
		{
			name: "v6-from16",
			fn:   IPFrom16,
			in:   [...]byte{15: 1},
			want: IP{z: z6noz, addr: uint128{0, 1}},
		},
		{
			name: "v4-raw",
			fn:   IPv6Raw,
			in:   [...]byte{10: 0xff, 11: 0xff, 12: 1, 13: 2, 14: 3, 15: 4},
			want: IP{z: z6noz, addr: uint128{0, 0xffff01020304}},
		},
		{
			name: "v4-from16",
			fn:   IPFrom16,
			in:   [...]byte{10: 0xff, 11: 0xff, 12: 1, 13: 2, 14: 3, 15: 4},
			want: IPv4(1, 2, 3, 4),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.fn(tt.in)
			if got != tt.want {
				t.Errorf("got %#v; want %#v", got, tt.want)
			}
		})
	}
}

func TestFromStdAddr(t *testing.T) {
	tests := []struct {
		name string
		ua   *net.UDPAddr
		want IPPort
	}{
		{
			name: "v4",
			ua: &net.UDPAddr{
				IP:   net.ParseIP("1.2.3.4"),
				Port: 567,
			},
			want: IPPort{mustIP("1.2.3.4"), 567},
		},
		{
			name: "v6",
			ua: &net.UDPAddr{
				IP:   net.ParseIP("::1"),
				Port: 567,
			},
			want: IPPort{mustIP("::1"), 567},
		},
		{
			name: "v6zone",
			ua: &net.UDPAddr{
				IP:   net.ParseIP("::1"),
				Port: 567,
				Zone: "foo",
			},
			want: IPPort{mustIP("::1").WithZone("foo"), 567},
		},
		{
			name: "v4zone_bad",
			ua: &net.UDPAddr{
				IP:   net.ParseIP("1.2.3.4"),
				Port: 567,
				Zone: "foo",
			},
			want: IPPort{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := FromStdAddr(tt.ua.IP, tt.ua.Port, tt.ua.Zone)
			if !ok {
				if got != (IPPort{}) {
					t.Fatalf("!ok but non-zero result")
				}
			}
			if got != tt.want {
				t.Errorf("got %+v; want %+v", got, tt.want)
			}
		})
	}
}

func TestIPProperties(t *testing.T) {
	var (
		nilIP IP

		unicast4           = mustIP("192.0.2.1")
		unicast6           = mustIP("2001:db8::1")
		unicastZone6       = mustIP("2001:db8::1%eth0")
		unicast6Unassigned = mustIP("4000::1") // not in 2000::/3.

		multicast4     = mustIP("224.0.0.1")
		multicast6     = mustIP("ff02::1")
		multicastZone6 = mustIP("ff02::1%eth0")

		llu4     = mustIP("169.254.0.1")
		llu6     = mustIP("fe80::1")
		llu6Last = mustIP("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
		lluZone6 = mustIP("fe80::1%eth0")

		loopback4 = mustIP("127.0.0.1")
		loopback6 = mustIP("::1")

		ilm6     = mustIP("ff01::1")
		ilmZone6 = mustIP("ff01::1%eth0")

		private4a = mustIP("10.0.0.1")
		private4b = mustIP("172.16.0.1")
		private4c = mustIP("192.168.1.1")
		private6  = mustIP("fd00::1")

		unspecified4 = IPv4(0, 0, 0, 0)
		unspecified6 = IPv6Unspecified()
	)

	tests := []struct {
		name                    string
		ip                      IP
		globalUnicast           bool
		interfaceLocalMulticast bool
		linkLocalMulticast      bool
		linkLocalUnicast        bool
		loopback                bool
		multicast               bool
		private                 bool
		unspecified             bool
	}{
		{
			name: "nil",
			ip:   nilIP,
		},
		{
			name:          "unicast v4Addr",
			ip:            unicast4,
			globalUnicast: true,
		},
		{
			name:          "unicast v6Addr",
			ip:            unicast6,
			globalUnicast: true,
		},
		{
			name:          "unicast v6AddrZone",
			ip:            unicastZone6,
			globalUnicast: true,
		},
		{
			name:          "unicast v6Addr unassigned",
			ip:            unicast6Unassigned,
			globalUnicast: true,
		},
		{
			name:               "multicast v4Addr",
			ip:                 multicast4,
			linkLocalMulticast: true,
			multicast:          true,
		},
		{
			name:               "multicast v6Addr",
			ip:                 multicast6,
			linkLocalMulticast: true,
			multicast:          true,
		},
		{
			name:               "multicast v6AddrZone",
			ip:                 multicastZone6,
			linkLocalMulticast: true,
			multicast:          true,
		},
		{
			name:             "link-local unicast v4Addr",
			ip:               llu4,
			linkLocalUnicast: true,
		},
		{
			name:             "link-local unicast v6Addr",
			ip:               llu6,
			linkLocalUnicast: true,
		},
		{
			name:             "link-local unicast v6Addr upper bound",
			ip:               llu6Last,
			linkLocalUnicast: true,
		},
		{
			name:             "link-local unicast v6AddrZone",
			ip:               lluZone6,
			linkLocalUnicast: true,
		},
		{
			name:     "loopback v4Addr",
			ip:       loopback4,
			loopback: true,
		},
		{
			name:     "loopback v6Addr",
			ip:       loopback6,
			loopback: true,
		},
		{
			name:                    "interface-local multicast v6Addr",
			ip:                      ilm6,
			interfaceLocalMulticast: true,
			multicast:               true,
		},
		{
			name:                    "interface-local multicast v6AddrZone",
			ip:                      ilmZone6,
			interfaceLocalMulticast: true,
			multicast:               true,
		},
		{
			name:          "private v4Addr 10/8",
			ip:            private4a,
			globalUnicast: true,
			private:       true,
		},
		{
			name:          "private v4Addr 172.16/12",
			ip:            private4b,
			globalUnicast: true,
			private:       true,
		},
		{
			name:          "private v4Addr 192.168/16",
			ip:            private4c,
			globalUnicast: true,
			private:       true,
		},
		{
			name:          "private v6Addr",
			ip:            private6,
			globalUnicast: true,
			private:       true,
		},
		{
			name:        "unspecified v4Addr",
			ip:          unspecified4,
			unspecified: true,
		},
		{
			name:        "unspecified v6Addr",
			ip:          unspecified6,
			unspecified: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gu := tt.ip.IsGlobalUnicast()
			if gu != tt.globalUnicast {
				t.Errorf("IsGlobalUnicast(%v) = %v; want %v", tt.ip, gu, tt.globalUnicast)
			}

			ilm := tt.ip.IsInterfaceLocalMulticast()
			if ilm != tt.interfaceLocalMulticast {
				t.Errorf("IsInterfaceLocalMulticast(%v) = %v; want %v", tt.ip, ilm, tt.interfaceLocalMulticast)
			}

			llu := tt.ip.IsLinkLocalUnicast()
			if llu != tt.linkLocalUnicast {
				t.Errorf("IsLinkLocalUnicast(%v) = %v; want %v", tt.ip, llu, tt.linkLocalUnicast)
			}

			llm := tt.ip.IsLinkLocalMulticast()
			if llm != tt.linkLocalMulticast {
				t.Errorf("IsLinkLocalMulticast(%v) = %v; want %v", tt.ip, llm, tt.linkLocalMulticast)
			}

			lo := tt.ip.IsLoopback()
			if lo != tt.loopback {
				t.Errorf("IsLoopback(%v) = %v; want %v", tt.ip, lo, tt.loopback)
			}

			multicast := tt.ip.IsMulticast()
			if multicast != tt.multicast {
				t.Errorf("IsMulticast(%v) = %v; want %v", tt.ip, multicast, tt.multicast)
			}

			private := tt.ip.IsPrivate()
			if private != tt.private {
				t.Errorf("IsPrivate(%v) = %v; want %v", tt.ip, private, tt.private)
			}

			unspecified := tt.ip.IsUnspecified()
			if unspecified != tt.unspecified {
				t.Errorf("IsUnspecified(%v) = %v; want %v", tt.ip, unspecified, tt.unspecified)
			}
		})
	}
}

func TestIPWellKnown(t *testing.T) {
	tests := []struct {
		name string
		ip   IP
		std  net.IP
	}{
		{
			name: "IPv6 link-local all nodes",
			ip:   IPv6LinkLocalAllNodes(),
			std:  net.IPv6linklocalallnodes,
		},
		{
			name: "IPv6 unspecified",
			ip:   IPv6Unspecified(),
			std:  net.IPv6unspecified,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := tt.std.String()
			got := tt.ip.String()

			if got != want {
				t.Fatalf("got %s, want %s", got, want)
			}
		})
	}
}

func TestLessCompare(t *testing.T) {
	tests := []struct {
		a, b IP
		want bool
	}{
		{IP{}, IP{}, false},
		{IP{}, mustIP("1.2.3.4"), true},
		{mustIP("1.2.3.4"), IP{}, false},

		{mustIP("1.2.3.4"), mustIP("0102:0304::0"), true},
		{mustIP("0102:0304::0"), mustIP("1.2.3.4"), false},
		{mustIP("1.2.3.4"), mustIP("1.2.3.4"), false},

		{mustIP("::1"), mustIP("::2"), true},
		{mustIP("::1"), mustIP("::1%foo"), true},
		{mustIP("::1%foo"), mustIP("::2"), true},
		{mustIP("::2"), mustIP("::3"), true},

		{mustIP("::"), mustIP("0.0.0.0"), false},
		{mustIP("0.0.0.0"), mustIP("::"), true},

		{mustIP("::1%a"), mustIP("::1%b"), true},
		{mustIP("::1%a"), mustIP("::1%a"), false},
		{mustIP("::1%b"), mustIP("::1%a"), false},
	}
	for _, tt := range tests {
		got := tt.a.Less(tt.b)
		if got != tt.want {
			t.Errorf("Less(%q, %q) = %v; want %v", tt.a, tt.b, got, tt.want)
		}
		cmp := tt.a.Compare(tt.b)
		if got && cmp != -1 {
			t.Errorf("Less(%q, %q) = true, but Compare = %v (not -1)", tt.a, tt.b, cmp)
		}
		if cmp < -1 || cmp > 1 {
			t.Errorf("bogus Compare return value %v", cmp)
		}
		if cmp == 0 && tt.a != tt.b {
			t.Errorf("Compare(%q, %q) = 0; but not equal", tt.a, tt.b)
		}
		if cmp == 1 && !tt.b.Less(tt.a) {
			t.Errorf("Compare(%q, %q) = 1; but b.Less(a) isn't true", tt.a, tt.b)
		}

		// Also check inverse.
		if got == tt.want && got {
			got2 := tt.b.Less(tt.a)
			if got2 {
				t.Errorf("Less(%q, %q) was correctly %v, but so was Less(%q, %q)", tt.a, tt.b, got, tt.b, tt.a)
			}
		}
	}

	// And just sort.
	values := []IP{
		mustIP("::1"),
		mustIP("::2"),
		IP{},
		mustIP("1.2.3.4"),
		mustIP("8.8.8.8"),
		mustIP("::1%foo"),
	}
	sort.Slice(values, func(i, j int) bool { return values[i].Less(values[j]) })
	got := fmt.Sprintf("%s", values)
	want := `[zero IP 1.2.3.4 8.8.8.8 ::1 ::1%foo ::2]`
	if got != want {
		t.Errorf("unexpected sort\n got: %s\nwant: %s\n", got, want)
	}
}

func TestIPStringExpanded(t *testing.T) {
	tests := []struct {
		ip IP
		s  string
	}{
		{
			ip: IP{},
			s:  "zero IP",
		},
		{
			ip: mustIP("192.0.2.1"),
			s:  "192.0.2.1",
		},
		{
			ip: mustIP("2001:db8::1"),
			s:  "2001:0db8:0000:0000:0000:0000:0000:0001",
		},
		{
			ip: mustIP("2001:db8::1%eth0"),
			s:  "2001:0db8:0000:0000:0000:0000:0000:0001%eth0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.ip.String(), func(t *testing.T) {
			want := tt.s
			got := tt.ip.StringExpanded()

			if got != want {
				t.Fatalf("got %s, want %s", got, want)
			}
		})
	}
}

func TestIPPrefixMasking(t *testing.T) {
	type subtest struct {
		ip   IP
		bits uint8
		p    IPPrefix
		ok   bool
	}

	// makeIPv6 produces a set of IPv6 subtests with an optional zone identifier.
	makeIPv6 := func(zone string) []subtest {
		if zone != "" {
			zone = "%" + zone
		}

		return []subtest{
			{
				ip:   mustIP(fmt.Sprintf("2001:db8::1%s", zone)),
				bits: 255,
			},
			{
				ip:   mustIP(fmt.Sprintf("2001:db8::1%s", zone)),
				bits: 32,
				p:    mustIPPrefix(fmt.Sprintf("2001:db8::%s/32", zone)),
				ok:   true,
			},
			{
				ip:   mustIP(fmt.Sprintf("fe80::dead:beef:dead:beef%s", zone)),
				bits: 96,
				p:    mustIPPrefix(fmt.Sprintf("fe80::dead:beef:0:0%s/96", zone)),
				ok:   true,
			},
			{
				ip:   mustIP(fmt.Sprintf("aaaa::%s", zone)),
				bits: 4,
				p:    mustIPPrefix(fmt.Sprintf("a000::%s/4", zone)),
				ok:   true,
			},
			{
				ip:   mustIP(fmt.Sprintf("::%s", zone)),
				bits: 63,
				p:    mustIPPrefix(fmt.Sprintf("::%s/63", zone)),
				ok:   true,
			},
		}
	}

	tests := []struct {
		family   string
		subtests []subtest
	}{
		{
			family: "nil",
			subtests: []subtest{
				{
					bits: 255,
					ok:   true,
				},
				{
					bits: 16,
					ok:   true,
				},
			},
		},
		{
			family: "IPv4",
			subtests: []subtest{
				{
					ip:   mustIP("192.0.2.0"),
					bits: 255,
				},
				{
					ip:   mustIP("192.0.2.0"),
					bits: 16,
					p:    mustIPPrefix("192.0.0.0/16"),
					ok:   true,
				},
				{
					ip:   mustIP("255.255.255.255"),
					bits: 20,
					p:    mustIPPrefix("255.255.240.0/20"),
					ok:   true,
				},
				{
					// Partially masking one byte that contains both
					// 1s and 0s on either side of the mask limit.
					ip:   mustIP("100.98.156.66"),
					bits: 10,
					p:    mustIPPrefix("100.64.0.0/10"),
					ok:   true,
				},
			},
		},
		{
			family:   "IPv6",
			subtests: makeIPv6(""),
		},
		{
			family:   "IPv6 zone",
			subtests: makeIPv6("eth0"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.family, func(t *testing.T) {
			for _, st := range tt.subtests {
				t.Run(st.p.String(), func(t *testing.T) {
					// Ensure st.ip is not mutated.
					orig := st.ip.String()

					p, err := st.ip.Prefix(st.bits)
					if st.ok && err != nil {
						t.Fatalf("failed to produce prefix: %v", err)
					}
					if !st.ok && err == nil {
						t.Fatal("expected an error, but none occurred")
					}
					if err != nil {
						t.Logf("err: %v", err)
						return
					}

					if !reflect.DeepEqual(p, st.p) {
						t.Errorf("prefix = %q, want %q", p, st.p)
					}

					if got := st.ip.String(); got != orig {
						t.Errorf("IP was mutated: %q, want %q", got, orig)
					}
				})
			}
		})
	}
}

func TestIPNetmasking(t *testing.T) {
	type subtest struct {
		ip   IP
		mask []byte
		p    IPPrefix
		ok   bool
	}

	// makeIPv6 produces a set of IPv6 subtests with an optional zone identifier.
	makeIPv6 := func(zone string) []subtest {
		if zone != "" {
			zone = "%" + zone
		}

		return []subtest{
			{
				ip: mustIP(fmt.Sprintf("2001:db8::1%s", zone)),
				mask: []byte{
					0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
					0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
					0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
					0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				},
			},
			{
				ip: mustIP(fmt.Sprintf("2001:db8::1%s", zone)),
				mask: []byte{
					0, 0, 0, 0, 0, 0, 0, 0,
					0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0,
				},
			},
			{
				ip: mustIP(fmt.Sprintf("2001:db8::1%s", zone)),
				mask: []byte{
					0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0,
					0, 0, 0, 0, 0, 0, 0, 0,
				},
				p:  mustIPPrefix(fmt.Sprintf("2001:db8::%s/32", zone)),
				ok: true,
			},
			{
				ip: mustIP(fmt.Sprintf("fe80::dead:beef:dead:beef%s", zone)),
				mask: []byte{
					0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
					0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0,
				},
				p:  mustIPPrefix(fmt.Sprintf("fe80::dead:beef:0:0%s/96", zone)),
				ok: true,
			},
			{
				ip: mustIP(fmt.Sprintf("aaaa::%s", zone)),
				mask: []byte{
					0xF0, 0, 0, 0, 0, 0, 0, 0,
					0, 0, 0, 0, 0, 0, 0, 0,
				},
				p:  mustIPPrefix(fmt.Sprintf("a000::%s/4", zone)),
				ok: true,
			},
			{
				ip: mustIP(fmt.Sprintf("::%s", zone)),
				mask: []byte{
					0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
					0, 0, 0, 0, 0, 0, 0, 0,
				},
				p:  mustIPPrefix(fmt.Sprintf("::%s/63", zone)),
				ok: true,
			},
		}
	}

	tests := []struct {
		family   string
		subtests []subtest
	}{
		{
			family: "nil",
			subtests: []subtest{
				{
					ok: true,
				},
			},
		},
		{
			family: "IPv4",
			subtests: []subtest{
				{
					ip: mustIP("192.0.2.0"),
					mask: []byte{
						0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
						0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
						0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
						0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
					},
				},
				{
					ip:   mustIP("192.0.2.0"),
					mask: []byte{0xFF, 0, 0xFF, 0},
				},
				{
					ip:   mustIP("192.0.2.0"),
					mask: []byte{0xFF, 0xFF, 0, 0},
					p:    mustIPPrefix("192.0.0.0/16"),
					ok:   true,
				},
				{
					ip:   mustIP("255.255.255.255"),
					mask: []byte{0xFF, 0xFF, 0xF0, 0},
					p:    mustIPPrefix("255.255.240.0/20"),
					ok:   true,
				},
				{
					// Partially masking one byte that contains both
					// 1s and 0s on either side of the mask limit.
					ip:   mustIP("100.98.156.66"),
					mask: []byte{0xFF, 0xC0, 0, 0},
					p:    mustIPPrefix("100.64.0.0/10"),
					ok:   true,
				},
			},
		},
		{
			family:   "IPv6",
			subtests: makeIPv6(""),
		},
		{
			family:   "IPv6 zone",
			subtests: makeIPv6("eth0"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.family, func(t *testing.T) {
			for _, st := range tt.subtests {
				t.Run(st.p.String(), func(t *testing.T) {
					origIP := st.ip.String()
					origMask := make([]byte, len(st.mask))
					copy(origMask, st.mask)

					p, err := st.ip.Netmask(st.mask)
					if st.ok && err != nil {
						t.Fatalf("failed to produce prefix: %v", err)
					}
					if !st.ok && err == nil {
						t.Fatal("expected an error, but none occurred")
					}

					if err != nil {
						t.Logf("err: %v", err)
						return
					}

					if !reflect.DeepEqual(p, st.p) {
						t.Errorf("prefix = %q, want %q", p, st.p)
					}

					if st.mask != nil && !reflect.DeepEqual(origMask, st.mask) {
						t.Errorf("Netmask was mutated: %q, want %q", origMask, st.mask)
					}

					if got := st.ip.String(); got != origIP {
						t.Errorf("IP was mutated: %q, want %q", got, origIP)
					}
				})
			}
		})
	}
}

func TestIPPrefixMarshalUnmarshal(t *testing.T) {
	tests := []string{
		"",
		"1.2.3.4/32",
		"0.0.0.0/0",
		"::/0",
		"::1/128",
		"::ffff:c000:1234/128",
		"2001:db8::/32",
	}

	for _, s := range tests {
		t.Run(s, func(t *testing.T) {
			// Ensure that JSON  (and by extension, text) marshaling is
			// sane by entering quoted input.
			orig := `"` + s + `"`

			var p IPPrefix
			if err := json.Unmarshal([]byte(orig), &p); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}

			pb, err := json.Marshal(p)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}

			back := string(pb)
			if orig != back {
				t.Errorf("Marshal = %q; want %q", back, orig)
			}
		})
	}
}

func TestIPPrefixMarshalUnmarshalZone(t *testing.T) {
	orig := `"fe80::1cc0:3e8c:119f:c2e1%ens18/128"`
	unzoned := `"fe80::1cc0:3e8c:119f:c2e1/128"`

	var p IPPrefix
	if err := json.Unmarshal([]byte(orig), &p); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	pb, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	back := string(pb)
	if back != unzoned {
		t.Errorf("Marshal = %q; want %q", back, unzoned)
	}
}

func TestIPPrefixUnmarshalTextNonZero(t *testing.T) {
	ip := mustIPPrefix("fe80::/64")
	if err := ip.UnmarshalText([]byte("xxx")); err == nil {
		t.Fatal("unmarshaled into non-empty IPPrefix")
	}
}

func TestIs4AndIs6(t *testing.T) {
	tests := []struct {
		ip  IP
		is4 bool
		is6 bool
	}{
		{IP{}, false, false},
		{mustIP("1.2.3.4"), true, false},
		{mustIP("127.0.0.2"), true, false},
		{mustIP("::1"), false, true},
		{mustIP("::ffff:192.0.2.128"), false, true},
		{mustIP("::fffe:c000:0280"), false, true},
		{mustIP("::1%eth0"), false, true},
	}
	for _, tt := range tests {
		got4 := tt.ip.Is4()
		if got4 != tt.is4 {
			t.Errorf("Is4(%q) = %v; want %v", tt.ip, got4, tt.is4)
		}

		got6 := tt.ip.Is6()
		if got6 != tt.is6 {
			t.Errorf("Is6(%q) = %v; want %v", tt.ip, got6, tt.is6)
		}
	}
}

func TestIs4In6(t *testing.T) {
	tests := []struct {
		ip        IP
		want      bool
		wantUnmap IP
	}{
		{IP{}, false, IP{}},
		{mustIP("::ffff:c000:0280"), true, mustIP("192.0.2.128")},
		{mustIP("::ffff:192.0.2.128"), true, mustIP("192.0.2.128")},
		{mustIP("::ffff:192.0.2.128%eth0"), true, mustIP("192.0.2.128")},
		{mustIP("::fffe:c000:0280"), false, mustIP("::fffe:c000:0280")},
		{mustIP("::ffff:127.001.002.003"), true, mustIP("127.1.2.3")},
		{mustIP("::ffff:7f01:0203"), true, mustIP("127.1.2.3")},
		{mustIP("0:0:0:0:0000:ffff:127.1.2.3"), true, mustIP("127.1.2.3")},
		{mustIP("0:0:0:0:000000:ffff:127.1.2.3"), true, mustIP("127.1.2.3")},
		{mustIP("0:0:0:0::ffff:127.1.2.3"), true, mustIP("127.1.2.3")},
		{mustIP("::1"), false, mustIP("::1")},
		{mustIP("1.2.3.4"), false, mustIP("1.2.3.4")},
	}
	for _, tt := range tests {
		got := tt.ip.Is4in6()
		if got != tt.want {
			t.Errorf("Is4in6(%q) = %v; want %v", tt.ip, got, tt.want)
		}
		u := tt.ip.Unmap()
		if u != tt.wantUnmap {
			t.Errorf("Unmap(%q) = %v; want %v", tt.ip, u, tt.wantUnmap)
		}
	}
}

func TestIPPrefixMasked(t *testing.T) {
	tests := []struct {
		prefix IPPrefix
		masked IPPrefix
	}{
		{
			prefix: mustIPPrefix("192.168.0.255/24"),
			masked: mustIPPrefix("192.168.0.0/24"),
		},
		{
			prefix: mustIPPrefix("2100::/3"),
			masked: mustIPPrefix("2000::/3"),
		},
		{
			prefix: IPPrefixFrom(mustIP("2000::"), 129),
			masked: IPPrefix{},
		},
		{
			prefix: IPPrefixFrom(mustIP("1.2.3.4"), 33),
			masked: IPPrefix{},
		},
	}
	for _, test := range tests {
		t.Run(test.prefix.String(), func(t *testing.T) {
			got := test.prefix.Masked()
			if got != test.masked {
				t.Errorf("Masked=%s, want %s", got, test.masked)
			}
		})
	}
}

func TestIPPrefix(t *testing.T) {
	tests := []struct {
		prefix      string
		ip          IP
		bits        uint8
		ipNet       *net.IPNet
		str         string
		contains    []IP
		notContains []IP
	}{
		{
			prefix: "192.168.0.0/24",
			ip:     mustIP("192.168.0.0"),
			bits:   24,
			ipNet: &net.IPNet{
				IP:   net.ParseIP("192.168.0.0"),
				Mask: net.CIDRMask(24, 32),
			},
			contains:    mustIPs("192.168.0.1", "192.168.0.55"),
			notContains: mustIPs("192.168.1.1", "1.1.1.1"),
		},
		{
			prefix: "192.168.1.1/32",
			ip:     mustIP("192.168.1.1"),
			bits:   32,
			ipNet: &net.IPNet{
				IP:   net.ParseIP("192.168.1.1"),
				Mask: net.CIDRMask(32, 32),
			},
			contains:    mustIPs("192.168.1.1"),
			notContains: mustIPs("192.168.1.2"),
		},
		{
			prefix: "100.64.0.0/10", // CGNAT range; prefix not multiple of 8
			ip:     mustIP("100.64.0.0"),
			bits:   10,
			ipNet: &net.IPNet{
				IP:   net.ParseIP("100.64.0.0"),
				Mask: net.CIDRMask(10, 32),
			},
			contains:    mustIPs("100.64.0.0", "100.64.0.1", "100.81.251.94", "100.100.100.100", "100.127.255.254", "100.127.255.255"),
			notContains: mustIPs("100.63.255.255", "100.128.0.0"),
		},
		{
			prefix: "2001:db8::/96",
			ip:     mustIP("2001:db8::"),
			bits:   96,
			ipNet: &net.IPNet{
				IP:   net.ParseIP("2001:db8::"),
				Mask: net.CIDRMask(96, 128),
			},
			contains:    mustIPs("2001:db8::aaaa:bbbb", "2001:db8::1"),
			notContains: mustIPs("2001:db8::1:aaaa:bbbb", "2001:db9::"),
		},
		{
			prefix: "0.0.0.0/0",
			ip:     mustIP("0.0.0.0"),
			bits:   0,
			ipNet: &net.IPNet{
				IP:   net.ParseIP("0.0.0.0"),
				Mask: net.CIDRMask(0, 32),
			},
			contains:    mustIPs("192.168.0.1", "1.1.1.1"),
			notContains: append(mustIPs("2001:db8::1"), IP{}),
		},
		{
			prefix: "::/0",
			ip:     mustIP("::"),
			bits:   0,
			ipNet: &net.IPNet{
				IP:   net.ParseIP("::"),
				Mask: net.CIDRMask(0, 128),
			},
			contains:    mustIPs("::1", "2001:db8::1"),
			notContains: mustIPs("192.0.2.1"),
		},
		{
			prefix: "2000::/3",
			ip:     mustIP("2000::"),
			bits:   3,
			ipNet: &net.IPNet{
				IP:   net.ParseIP("2000::"),
				Mask: net.CIDRMask(3, 128),
			},
			contains:    mustIPs("2001:db8::1"),
			notContains: mustIPs("fe80::1"),
		},
		{
			prefix: "::%0/00/80",
			ip:     mustIP("::"),
			bits:   80,
			str:    "::/80",
			ipNet: &net.IPNet{
				IP:   net.ParseIP("::"), // net.IPNet drops zones
				Mask: net.CIDRMask(80, 128),
			},
			contains:    mustIPs("::"),
			notContains: mustIPs("ff::%0/00", "ff::%1/23", "::%0/00", "::%1/23"),
		},
	}
	for _, test := range tests {
		t.Run(test.prefix, func(t *testing.T) {
			prefix, err := ParseIPPrefix(test.prefix)
			if err != nil {
				t.Fatal(err)
			}
			if prefix.IP() != test.ip {
				t.Errorf("IP=%s, want %s", prefix.IP(), test.ip)
			}
			if prefix.Bits() != test.bits {
				t.Errorf("bits=%d, want %d", prefix.Bits(), test.bits)
			}
			stdIPNet := prefix.IPNet()
			if !test.ipNet.IP.Equal(stdIPNet.IP) || !reflect.DeepEqual(stdIPNet.Mask, test.ipNet.Mask) {
				t.Errorf("IPNet=%v, want %v", stdIPNet, test.ipNet)
			}
			for _, ip := range test.contains {
				if !prefix.Contains(ip) {
					t.Errorf("does not contain %s", ip)
				}
			}
			for _, ip := range test.notContains {
				if prefix.Contains(ip) {
					t.Errorf("contains %s", ip)
				}
			}
			want := test.str
			if want == "" {
				want = test.prefix
			}
			if got := prefix.String(); got != want {
				t.Errorf("prefix.String()=%q, want %q", got, want)
			}

			testAppendToMarshal(t, prefix)
		})
	}
}

func TestIPPrefixValid(t *testing.T) {
	v4 := MustParseIP("1.2.3.4")
	v6 := MustParseIP("::1")
	tests := []struct {
		ipp  IPPrefix
		want bool
	}{
		{IPPrefix{v4, 0}, true},
		{IPPrefix{v4, 32}, true},
		{IPPrefix{v4, 33}, false},
		{IPPrefix{v6, 0}, true},
		{IPPrefix{v6, 32}, true},
		{IPPrefix{v6, 128}, true},
		{IPPrefix{v6, 129}, false},
		{IPPrefix{IP{}, 0}, false},
		{IPPrefix{IP{}, 32}, false},
		{IPPrefix{IP{}, 128}, false},
	}
	for _, tt := range tests {
		got := tt.ipp.IsValid()
		if got != tt.want {
			t.Errorf("(%v).IsValid() = %v want %v", tt.ipp, got, tt.want)
		}
	}
}

func TestFromStdIPNet(t *testing.T) {
	tests := []struct {
		name string
		std  *net.IPNet
		want IPPrefix
	}{
		{
			name: "invalid IP",
			std: &net.IPNet{
				IP: net.IP{0xff},
			},
		},
		{
			name: "invalid mask",
			std: &net.IPNet{
				IP:   net.IPv6loopback,
				Mask: nil,
			},
		},
		{
			name: "non-contiguous mask",
			std: &net.IPNet{
				IP:   net.IPv4(192, 0, 2, 0).To4(),
				Mask: net.IPv4Mask(255, 0, 255, 0),
			},
		},
		{
			name: "IPv4",
			std: &net.IPNet{
				IP:   net.IPv4(192, 0, 2, 0).To4(),
				Mask: net.CIDRMask(24, 32),
			},
			want: mustIPPrefix("192.0.2.0/24"),
		},
		{
			name: "IPv6",
			std: &net.IPNet{
				IP:   net.ParseIP("2001:db8::"),
				Mask: net.CIDRMask(64, 128),
			},
			want: mustIPPrefix("2001:db8::/64"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := FromStdIPNet(tt.std)
			if !ok && got != (IPPrefix{}) {
				t.Fatalf("!ok but non-zero result")
			}

			if got != tt.want {
				t.Errorf("FromStdIPNet(%q) = %+v; want %+v", tt.std, got, tt.want)
			}
		})
	}
}

func TestParseIPPrefixAllocs(t *testing.T) {
	tests := []struct {
		ip    string
		slash string
	}{
		{"192.168.1.0", "/24"},
		{"aaaa:bbbb:cccc::", "/24"},
	}
	for _, test := range tests {
		prefix := test.ip + test.slash
		t.Run(prefix, func(t *testing.T) {
			ipAllocs := int(testing.AllocsPerRun(5, func() {
				ParseIP(test.ip)
			}))
			prefixAllocs := int(testing.AllocsPerRun(5, func() {
				ParseIPPrefix(prefix)
			}))
			if got := prefixAllocs - ipAllocs; got != 0 {
				t.Errorf("allocs=%d, want 0", got)
			}
		})
	}
}

func TestParseIPPrefixError(t *testing.T) {
	tests := []struct {
		prefix string
		errstr string
	}{
		{
			prefix: "192.168.0.0",
			errstr: "no '/'",
		},
		{
			prefix: "1.257.1.1/24",
			errstr: "value >255",
		},
		{
			prefix: "1.1.1.0/q",
			errstr: "bad prefix",
		},
		{
			prefix: "1.1.1.0/-1",
			errstr: "out of range",
		},
		{
			prefix: "1.1.1.0/33",
			errstr: "out of range",
		},
		{
			prefix: "2001::/129",
			errstr: "out of range",
		},
	}
	for _, test := range tests {
		t.Run(test.prefix, func(t *testing.T) {
			_, err := ParseIPPrefix(test.prefix)
			if err == nil {
				t.Fatal("no error")
			}
			if got := err.Error(); !strings.Contains(got, test.errstr) {
				t.Errorf("error is missing substring %q: %s", test.errstr, got)
			}
		})
	}
}

func TestIPPrefixIsSingleIP(t *testing.T) {
	tests := []struct {
		ipp  IPPrefix
		want bool
	}{
		{ipp: mustIPPrefix("127.0.0.1/32"), want: true},
		{ipp: mustIPPrefix("127.0.0.1/31"), want: false},
		{ipp: mustIPPrefix("127.0.0.1/0"), want: false},
		{ipp: mustIPPrefix("::1/128"), want: true},
		{ipp: mustIPPrefix("::1/127"), want: false},
		{ipp: mustIPPrefix("::1/0"), want: false},
		{ipp: IPPrefix{}, want: false},
	}
	for _, tt := range tests {
		got := tt.ipp.IsSingleIP()
		if got != tt.want {
			t.Errorf("IsSingleIP(%v) = %v want %v", tt.ipp, got, tt.want)
		}
	}
}

func TestParseIPError(t *testing.T) {
	tests := []struct {
		ip     string
		errstr string
	}{
		{
			ip: "localhost",
		},
		{
			ip:     "500.0.0.1",
			errstr: "field has value >255",
		},
		{
			ip:     "::gggg%eth0",
			errstr: "must have at least one digit",
		},
		{
			ip:     "fe80::1cc0:3e8c:119f:c2e1%",
			errstr: "zone must be a non-empty string",
		},
		{
			ip:     "%eth0",
			errstr: "missing IPv6 address",
		},
	}
	for _, test := range tests {
		t.Run(test.ip, func(t *testing.T) {
			_, err := ParseIP(test.ip)
			if err == nil {
				t.Fatal("no error")
			}
			if _, ok := err.(parseIPError); !ok {
				t.Errorf("error type is %T, want parseIPError", err)
			}
			if test.errstr == "" {
				test.errstr = "unable to parse IP"
			}
			if got := err.Error(); !strings.Contains(got, test.errstr) {
				t.Errorf("error is missing substring %q: %s", test.errstr, got)
			}
		})
	}
}

func TestParseIPPort(t *testing.T) {
	tests := []struct {
		in      string
		want    IPPort
		wantErr bool
	}{
		{in: "1.2.3.4:1234", want: IPPort{mustIP("1.2.3.4"), 1234}},
		{in: "1.1.1.1:123456", wantErr: true},
		{in: "1.1.1.1:-123", wantErr: true},
		{in: "[::1]:1234", want: IPPort{mustIP("::1"), 1234}},
		{in: "[1.2.3.4]:1234", wantErr: true},
		{in: "fe80::1:1234", wantErr: true},
		{in: ":0", wantErr: true}, // if we need to parse this form, there should be a separate function that explicitly allows it
	}
	for _, test := range tests {
		t.Run(test.in, func(t *testing.T) {
			got, err := ParseIPPort(test.in)
			if err != nil {
				if test.wantErr {
					return
				}
				t.Fatal(err)
			}
			if got != test.want {
				t.Errorf("got %v; want %v", got, test.want)
			}
			if got.String() != test.in {
				t.Errorf("String = %q; want %q", got.String(), test.in)
			}
		})

		t.Run(test.in+"/AppendTo", func(t *testing.T) {
			got, err := ParseIPPort(test.in)
			if err == nil {
				testAppendToMarshal(t, got)
			}
		})

		// TextMarshal and TextUnmarshal mostly behave like
		// ParseIPPort and String. Divergent behavior are handled in
		// TestIPPortMarshalUnmarshal.
		t.Run(test.in+"/Marshal", func(t *testing.T) {
			var got IPPort
			jsin := `"` + test.in + `"`
			err := json.Unmarshal([]byte(jsin), &got)
			if err != nil {
				if test.wantErr {
					return
				}
				t.Fatal(err)
			}
			if got != test.want {
				t.Errorf("got %v; want %v", got, test.want)
			}
			gotb, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			if string(gotb) != jsin {
				t.Errorf("Marshal = %q; want %q", string(gotb), jsin)
			}
		})
	}
}

func TestIPPortMarshalUnmarshal(t *testing.T) {
	tests := []struct {
		in   string
		want IPPort
	}{
		{"", IPPort{}},
	}

	for _, test := range tests {
		t.Run(test.in, func(t *testing.T) {
			orig := `"` + test.in + `"`

			var ipp IPPort
			if err := json.Unmarshal([]byte(orig), &ipp); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}

			ippb, err := json.Marshal(ipp)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}

			back := string(ippb)
			if orig != back {
				t.Errorf("Marshal = %q; want %q", back, orig)
			}

			testAppendToMarshal(t, ipp)
		})
	}
}

type appendMarshaler interface {
	encoding.TextMarshaler
	AppendTo([]byte) []byte
}

// testAppendToMarshal tests that x's AppendTo and MarshalText methods yield the same results.
// x's MarshalText method must not return an error.
func testAppendToMarshal(t *testing.T, x appendMarshaler) {
	t.Helper()
	m, err := x.MarshalText()
	if err != nil {
		t.Fatalf("(%v).MarshalText: %v", x, err)
	}
	a := make([]byte, 0, len(m))
	a = x.AppendTo(a)
	if !bytes.Equal(m, a) {
		t.Errorf("(%v).MarshalText = %q, (%v).AppendTo = %q", x, m, x, a)
	}
}

func TestUDPAddrAllocs(t *testing.T) {
	for _, ep := range []string{"1.2.3.4:1234", "[::1]:1234"} {
		ipp, err := ParseIPPort(ep)
		if err != nil {
			t.Fatalf("invalid %q", ep)
		}
		ua := &net.UDPAddr{IP: make(net.IP, 0, 16)}
		n := int(testing.AllocsPerRun(1000, func() {
			ua := ipp.UDPAddrAt(ua)
			if ua.Port != int(ipp.Port()) {
				t.Fatal("UDPAddr returned bogus result")
			}
		}))
		if n > 0 {
			t.Errorf("%d allocs for %q", n, ep)
		}
	}
}

var (
	mustIP       = MustParseIP
	mustIPPrefix = MustParseIPPrefix
)

func mustIPs(strs ...string) []IP {
	var res []IP
	for _, s := range strs {
		res = append(res, mustIP(s))
	}
	return res
}

func BenchmarkBinaryMarshalRoundTrip(b *testing.B) {
	b.ReportAllocs()
	tests := []struct {
		name string
		ip   string
	}{
		{"ipv4", "1.2.3.4"},
		{"ipv6", "2001:db8::1"},
		{"ipv6+zone", "2001:db8::1%eth0"},
	}
	for _, tc := range tests {
		b.Run(tc.name, func(b *testing.B) {
			ip := mustIP(tc.ip)
			for i := 0; i < b.N; i++ {
				bt, err := ip.MarshalBinary()
				if err != nil {
					b.Fatal(err)
				}
				var ip2 IP
				if err := ip2.UnmarshalBinary(bt); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkStdIPv4(b *testing.B) {
	b.ReportAllocs()
	ips := []net.IP{}
	for i := 0; i < b.N; i++ {
		ip := net.IPv4(8, 8, 8, 8)
		ips = ips[:0]
		for i := 0; i < 100; i++ {
			ips = append(ips, ip)
		}
	}
}

func BenchmarkIPv4(b *testing.B) {
	b.ReportAllocs()
	ips := []IP{}
	for i := 0; i < b.N; i++ {
		ip := IPv4(8, 8, 8, 8)
		ips = ips[:0]
		for i := 0; i < 100; i++ {
			ips = append(ips, ip)
		}
	}
}

// ip4i was one of the possible representations of IP that came up in
// discussions, inlining IPv4 addresses, but having an "overflow"
// interface for IPv6 or IPv6 + zone. This is here for benchmarking.
type ip4i struct {
	ip4    [4]byte
	flags1 byte
	flags2 byte
	flags3 byte
	flags4 byte
	ipv6   interface{}
}

func newip4i_v4(a, b, c, d byte) ip4i {
	return ip4i{ip4: [4]byte{a, b, c, d}}
}

// BenchmarkIPv4_inline benchmarks the candidate representation, ip4i.
func BenchmarkIPv4_inline(b *testing.B) {
	b.ReportAllocs()
	ips := []ip4i{}
	for i := 0; i < b.N; i++ {
		ip := newip4i_v4(8, 8, 8, 8)
		ips = ips[:0]
		for i := 0; i < 100; i++ {
			ips = append(ips, ip)
		}
	}
}

func BenchmarkStdIPv6(b *testing.B) {
	b.ReportAllocs()
	ips := []net.IP{}
	for i := 0; i < b.N; i++ {
		ip := net.ParseIP("2001:db8::1")
		ips = ips[:0]
		for i := 0; i < 100; i++ {
			ips = append(ips, ip)
		}
	}
}

func BenchmarkIPv6(b *testing.B) {
	b.ReportAllocs()
	ips := []IP{}
	for i := 0; i < b.N; i++ {
		ip := mustIP("2001:db8::1")
		ips = ips[:0]
		for i := 0; i < 100; i++ {
			ips = append(ips, ip)
		}
	}
}

func BenchmarkIPv4Contains(b *testing.B) {
	b.ReportAllocs()
	prefix := IPPrefixFrom(IPv4(192, 168, 1, 0), 24)
	ip := IPv4(192, 168, 1, 1)
	for i := 0; i < b.N; i++ {
		prefix.Contains(ip)
	}
}

func BenchmarkIPv6Contains(b *testing.B) {
	b.ReportAllocs()
	prefix := MustParseIPPrefix("::1/128")
	ip := MustParseIP("::1")
	for i := 0; i < b.N; i++ {
		prefix.Contains(ip)
	}
}

var parseBenchInputs = []struct {
	name string
	ip   string
}{
	{"v4", "192.168.1.1"},
	{"v6", "fd7a:115c:a1e0:ab12:4843:cd96:626b:430b"},
	{"v6_ellipsis", "fd7a:115c::626b:430b"},
	{"v6_v4", "::ffff:192.168.140.255"},
	{"v6_zone", "1:2::ffff:192.168.140.255%eth1"},
}

func BenchmarkParseIP(b *testing.B) {
	sinkInternValue = intern.Get("eth1") // Pin to not benchmark the intern package
	for _, test := range parseBenchInputs {
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sinkIP, _ = ParseIP(test.ip)
			}
		})
	}
}

func BenchmarkStdParseIP(b *testing.B) {
	for _, test := range parseBenchInputs {
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sinkStdIP = net.ParseIP(test.ip)
			}
		})
	}
}

func BenchmarkIPString(b *testing.B) {
	for _, test := range parseBenchInputs {
		ip := MustParseIP(test.ip)
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sinkString = ip.String()
			}
		})
	}
}

func BenchmarkIPStringExpanded(b *testing.B) {
	for _, test := range parseBenchInputs {
		ip := MustParseIP(test.ip)
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sinkString = ip.StringExpanded()
			}
		})
	}
}

func BenchmarkIPMarshalText(b *testing.B) {
	b.ReportAllocs()
	ip := MustParseIP("66.55.44.33")
	for i := 0; i < b.N; i++ {
		sinkBytes, _ = ip.MarshalText()
	}
}

func BenchmarkIPPortString(b *testing.B) {
	for _, test := range parseBenchInputs {
		ip := MustParseIP(test.ip)
		ipp := IPPortFrom(ip, 60000)
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sinkString = ipp.String()
			}
		})
	}
}

func BenchmarkIPPortMarshalText(b *testing.B) {
	for _, test := range parseBenchInputs {
		ip := MustParseIP(test.ip)
		ipp := IPPortFrom(ip, 60000)
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sinkBytes, _ = ipp.MarshalText()
			}
		})
	}
}

func BenchmarkIPPrefixMasking(b *testing.B) {
	tests := []struct {
		name string
		ip   IP
		bits uint8
	}{
		{
			name: "IPv4 /32",
			ip:   IPv4(192, 0, 2, 0),
			bits: 32,
		},
		{
			name: "IPv4 /17",
			ip:   IPv4(192, 0, 2, 0),
			bits: 17,
		},
		{
			name: "IPv4 /0",
			ip:   IPv4(192, 0, 2, 0),
			bits: 0,
		},
		{
			name: "IPv6 /128",
			ip:   mustIP("2001:db8::1"),
			bits: 128,
		},
		{
			name: "IPv6 /65",
			ip:   mustIP("2001:db8::1"),
			bits: 65,
		},
		{
			name: "IPv6 /0",
			ip:   mustIP("2001:db8::1"),
			bits: 0,
		},
		{
			name: "IPv6 zone /128",
			ip:   mustIP("2001:db8::1%eth0"),
			bits: 128,
		},
		{
			name: "IPv6 zone /65",
			ip:   mustIP("2001:db8::1%eth0"),
			bits: 65,
		},
		{
			name: "IPv6 zone /0",
			ip:   mustIP("2001:db8::1%eth0"),
			bits: 0,
		},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				sinkIPPrefix, _ = tt.ip.Prefix(tt.bits)
			}
		})
	}
}

func BenchmarkIPPrefixMarshalText(b *testing.B) {
	b.ReportAllocs()
	ipp := MustParseIPPrefix("66.55.44.33/22")
	for i := 0; i < b.N; i++ {
		sinkBytes, _ = ipp.MarshalText()
	}
}

func BenchmarkParseIPPort(b *testing.B) {
	for _, test := range parseBenchInputs {
		var ipp string
		if strings.HasPrefix(test.name, "v6") {
			ipp = fmt.Sprintf("[%s]:1234", test.ip)
		} else {
			ipp = fmt.Sprintf("%s:1234", test.ip)
		}
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				sinkIPPort, _ = ParseIPPort(ipp)
			}
		})
	}
}

func TestAs4(t *testing.T) {
	tests := []struct {
		ip        IP
		want      [4]byte
		wantPanic bool
	}{
		{
			ip:   mustIP("1.2.3.4"),
			want: [4]byte{1, 2, 3, 4},
		},
		{
			ip:   IPv6Raw(mustIP("1.2.3.4").As16()), // IPv4-in-IPv6
			want: [4]byte{1, 2, 3, 4},
		},
		{
			ip:   mustIP("0.0.0.0"),
			want: [4]byte{0, 0, 0, 0},
		},
		{
			ip:        IP{},
			wantPanic: true,
		},
		{
			ip:        mustIP("::1"),
			wantPanic: true,
		},
	}
	as4 := func(ip IP) (v [4]byte, gotPanic bool) {
		defer func() {
			if recover() != nil {
				gotPanic = true
				return
			}
		}()
		v = ip.As4()
		return
	}
	for i, tt := range tests {
		got, gotPanic := as4(tt.ip)
		if gotPanic != tt.wantPanic {
			t.Errorf("%d. panic on %v = %v; want %v", i, tt.ip, gotPanic, tt.wantPanic)
			continue
		}
		if got != tt.want {
			t.Errorf("%d. %v = %v; want %v", i, tt.ip, got, tt.want)
		}
	}
}

func TestIPPrefixLastIP(t *testing.T) {
	tests := []struct {
		prefix, want string
	}{
		{"10.0.0.0/8", "10.255.255.255"},
		{"10.0.0.0/9", "10.127.255.255"},
		{"0.0.0.0/0", "255.255.255.255"},
		{"0.0.0.0/32", "0.0.0.0"},
		{"::/0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		{"::/128", "::"},
	}
	for _, tt := range tests {
		p := mustIPPrefix(tt.prefix)
		got := p.lastIP()
		if got != mustIP(tt.want) {
			t.Errorf("LastIP(%v) = %v; want %v", tt.prefix, got, tt.want)
		}
	}
}

func TestIPPrefixOverlaps(t *testing.T) {
	pfx := mustIPPrefix
	tests := []struct {
		a, b IPPrefix
		want bool
	}{
		{IPPrefix{}, pfx("1.2.0.0/16"), false},  // first zero
		{pfx("1.2.0.0/16"), IPPrefix{}, false},  // second zero
		{pfx("::0/3"), pfx("0.0.0.0/3"), false}, // different families

		{pfx("1.2.0.0/16"), pfx("1.2.0.0/16"), true}, // equal

		{pfx("1.2.0.0/16"), pfx("1.2.3.0/24"), true},
		{pfx("1.2.3.0/24"), pfx("1.2.0.0/16"), true},

		{pfx("1.2.0.0/16"), pfx("1.2.3.0/32"), true},
		{pfx("1.2.3.0/32"), pfx("1.2.0.0/16"), true},

		// Match /0 either order
		{pfx("1.2.3.0/32"), pfx("0.0.0.0/0"), true},
		{pfx("0.0.0.0/0"), pfx("1.2.3.0/32"), true},

		{pfx("1.2.3.0/32"), pfx("5.5.5.5/0"), true}, // normalization not required; /0 means true

		// IPv6 overlapping
		{pfx("5::1/128"), pfx("5::0/8"), true},
		{pfx("5::0/8"), pfx("5::1/128"), true},

		// IPv6 not overlapping
		{pfx("1::1/128"), pfx("2::2/128"), false},
		{pfx("0100::0/8"), pfx("::1/128"), false},

		// v6-mapped v4 should not overlap with IPv4.
		{IPPrefixFrom(IPv6Raw(mustIP("1.2.0.0").As16()), 16), pfx("1.2.3.0/24"), false},

		// Invalid prefixes
		{IPPrefixFrom(mustIP("1.2.3.4"), 33), pfx("1.2.3.0/24"), false},
		{IPPrefixFrom(mustIP("2000::"), 129), pfx("2000::/64"), false},
	}
	for i, tt := range tests {
		if got := tt.a.Overlaps(tt.b); got != tt.want {
			t.Errorf("%d. (%v).Overlaps(%v) = %v; want %v", i, tt.a, tt.b, got, tt.want)
		}
		// Overlaps is commutative
		if got := tt.b.Overlaps(tt.a); got != tt.want {
			t.Errorf("%d. (%v).Overlaps(%v) = %v; want %v", i, tt.b, tt.a, got, tt.want)
		}
	}
}

func pxv(cidrStrs ...string) (out []IPPrefix) {
	for _, s := range cidrStrs {
		out = append(out, mustIPPrefix(s))
	}
	return
}

func TestRangePrefixes(t *testing.T) {
	tests := []struct {
		from string
		to   string
		want []IPPrefix
	}{
		{"0.0.0.0", "255.255.255.255", pxv("0.0.0.0/0")},
		{"::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", pxv("::/0")},
		{"10.0.0.0", "10.255.255.255", pxv("10.0.0.0/8")},
		{"10.0.0.0", "10.127.255.255", pxv("10.0.0.0/9")},
		{"0.0.0.4", "0.0.0.11", pxv(
			// 4 0100
			// 5 0101
			// 6 0110
			// 7 0111
			// 8 1000
			// 9 1001
			//10 1010
			//11 1011
			"0.0.0.4/30",
			"0.0.0.8/30",
		)},
		{"10.0.0.0", "11.10.255.255", pxv(
			"10.0.0.0/8",
			"11.0.0.0/13",
			"11.8.0.0/15",
			"11.10.0.0/16",
		)},
		{"1.2.3.5", "5.6.7.8", pxv(
			"1.2.3.5/32",
			"1.2.3.6/31",
			"1.2.3.8/29",
			"1.2.3.16/28",
			"1.2.3.32/27",
			"1.2.3.64/26",
			"1.2.3.128/25",
			"1.2.4.0/22",
			"1.2.8.0/21",
			"1.2.16.0/20",
			"1.2.32.0/19",
			"1.2.64.0/18",
			"1.2.128.0/17",
			"1.3.0.0/16",
			"1.4.0.0/14",
			"1.8.0.0/13",
			"1.16.0.0/12",
			"1.32.0.0/11",
			"1.64.0.0/10",
			"1.128.0.0/9",
			"2.0.0.0/7",
			"4.0.0.0/8",
			"5.0.0.0/14",
			"5.4.0.0/15",
			"5.6.0.0/22",
			"5.6.4.0/23",
			"5.6.6.0/24",
			"5.6.7.0/29",
			"5.6.7.8/32",
		)},
	}
	for _, tt := range tests {
		r := IPRangeFrom(mustIP(tt.from), mustIP(tt.to))
		got := r.Prefixes()
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("failed %s->%s. got:", tt.from, tt.to)
			for _, v := range got {
				t.Errorf("  %v", v)
			}
			t.Error("want:\n")
			for _, v := range tt.want {
				t.Errorf("  %v", v)
			}
		}
	}
}

func BenchmarkIPRangePrefixes(b *testing.B) {
	b.ReportAllocs()
	buf := make([]IPPrefix, 0, 50)
	r := IPRange{mustIP("1.2.3.5"), mustIP("5.6.7.8")}
	for i := 0; i < b.N; i++ {
		_ = r.AppendPrefixes(buf[:0])
	}
}

func TestParseIPRange(t *testing.T) {
	tests := []struct {
		in   string
		want interface{}
	}{
		{"", "no hyphen in range \"\""},
		{"foo-", `invalid From IP "foo" in range "foo-"`},
		{"1.2.3.4-foo", `invalid To IP "foo" in range "1.2.3.4-foo"`},
		{"1.2.3.4-5.6.7.8", IPRange{mustIP("1.2.3.4"), mustIP("5.6.7.8")}},
		{"1.2.3.4-0.1.2.3", "range 1.2.3.4 to 0.1.2.3 not valid"},
		{"::1-::5", IPRange{mustIP("::1"), mustIP("::5")}},
	}
	for _, tt := range tests {
		r, err := ParseIPRange(tt.in)
		var got interface{}
		if err != nil {
			got = err.Error()
		} else {
			got = r
		}
		if got != tt.want {
			t.Errorf("ParseIPRange(%q) = %v; want %v", tt.in, got, tt.want)
		}
		if err == nil {
			back := r.String()
			if back != tt.in {
				t.Errorf("input %q stringifies back as %q", tt.in, back)
			}
		}

		var r2 IPRange
		err = r2.UnmarshalText([]byte(tt.in))
		if err != nil {
			got = err.Error()
		} else {
			got = r2
		}
		if got != tt.want && tt.in != "" {
			t.Errorf("UnmarshalText(%q) = %v; want %v", tt.in, got, tt.want)
		}

		testAppendToMarshal(t, r)
	}
}

func TestIPRangeUnmarshalTextNonZero(t *testing.T) {
	r := MustParseIPRange("1.2.3.4-5.6.7.8")
	if err := r.UnmarshalText([]byte("1.2.3.4-5.6.7.8")); err == nil {
		t.Fatal("unmarshaled into non-empty IPPrefix")
	}
}

func TestIPRangeContains(t *testing.T) {
	type rtest struct {
		ip   IP
		want bool
	}
	tests := []struct {
		r      IPRange
		rtests []rtest
	}{
		{
			IPRangeFrom(mustIP("10.0.0.2"), mustIP("10.0.0.4")),
			[]rtest{
				{mustIP("10.0.0.1"), false},
				{mustIP("10.0.0.2"), true},
				{mustIP("10.0.0.3"), true},
				{mustIP("10.0.0.4"), true},
				{mustIP("10.0.0.5"), false},
				{IP{}, false},
				{mustIP("::"), false},
			},
		},
		{
			IPRangeFrom(mustIP("::1"), mustIP("::ffff")),
			[]rtest{
				{mustIP("::0"), false},
				{mustIP("::1"), true},
				{mustIP("::1%z"), false},
				{mustIP("::ffff"), true},
				{mustIP("1::"), false},
				{mustIP("0.0.0.1"), false},
				{IP{}, false},
			},
		},
		{
			IPRangeFrom(mustIP("10.0.0.2"), mustIP("::")), // invalid
			[]rtest{
				{mustIP("10.0.0.2"), false},
			},
		},
		{
			IPRange{},
			[]rtest{
				{IP{}, false},
			},
		},
	}
	for _, tt := range tests {
		for _, rt := range tt.rtests {
			got := tt.r.Contains(rt.ip)
			if got != rt.want {
				t.Errorf("Range(%v).Contains(%v) = %v; want %v", tt.r, rt.ip, got, rt.want)
			}
		}
	}
}

func TestIPRangeOverlaps(t *testing.T) {
	tests := []struct {
		r, o IPRange
		want bool
	}{
		{
			IPRange{},
			IPRange{},
			false,
		},
		{
			IPRange{mustIP("10.0.0.1"), mustIP("10.0.0.3")},
			IPRange{mustIP("10.0.0.3"), mustIP("10.0.0.4")},
			true, // overlaps on edge
		},
		{
			IPRange{mustIP("10.0.0.1"), mustIP("10.0.0.3")},
			IPRange{mustIP("10.0.0.2"), mustIP("10.0.0.4")},
			true, // overlaps in middle
		},
		{
			IPRange{mustIP("10.0.0.1"), mustIP("10.0.0.3")},
			IPRange{mustIP("10.0.0.4"), mustIP("10.0.0.4")},
			false, // doesn't overlap
		},
		{
			IPRange{mustIP("10.0.0.1"), mustIP("10.0.0.3")},
			IPRange{mustIP("10.0.0.0"), mustIP("10.0.0.5")},
			true, // one fully inside the other
		},
		{
			IPRange{mustIP("10.0.0.1"), mustIP("10.0.0.3")},
			IPRange{mustIP("::1"), mustIP("::2")},
			false,
		},
		{
			IPRange{mustIP("::"), mustIP("ff::")},
			IPRange{mustIP("cc::1"), mustIP("cc::2")},
			true,
		},
	}
	for _, tt := range tests {
		got := tt.r.Overlaps(tt.o)
		if got != tt.want {
			t.Errorf("Overlaps(%v, %v) = %v; want %v", tt.r, tt.o, got, tt.want)
		}
		got = tt.o.Overlaps(tt.r)
		if got != tt.want {
			t.Errorf("Overlaps(%v, %v) (reversed) = %v; want %v", tt.o, tt.r, got, tt.want)
		}
	}
}

func TestIPRangeValid(t *testing.T) {
	tests := []struct {
		r    IPRange
		want bool
	}{
		{IPRange{mustIP("10.0.0.0"), mustIP("10.0.0.255")}, true},
		{IPRange{mustIP("::1"), mustIP("::2")}, true},
		{IPRange{mustIP("::1%foo"), mustIP("::2%foo")}, true},

		{IPRange{mustIP("::1%foo"), mustIP("::2%bar")}, false}, // zones differ
		{IPRange{IP{}, IP{}}, false},                           // zero values
		{IPRange{mustIP("::2"), mustIP("::1")}, false},         // bad order
		{IPRange{mustIP("1.2.3.4"), mustIP("::1")}, false},     // family mismatch
	}
	for _, tt := range tests {
		got := tt.r.IsValid()
		if got != tt.want {
			t.Errorf("range %v to %v Valid = %v; want %v", tt.r.From(), tt.r.To(), got, tt.want)
		}
	}
}

func TestIPRangePrefix(t *testing.T) {
	tests := []struct {
		r    IPRange
		want IPPrefix
	}{
		{IPRange{mustIP("10.0.0.0"), mustIP("10.0.0.255")}, mustIPPrefix("10.0.0.0/24")},
		{IPRange{mustIP("10.0.0.0"), mustIP("10.0.0.254")}, IPPrefix{}},
		{IPRange{mustIP("fc00::"), mustIP("fe00::").Prior()}, mustIPPrefix("fc00::/7")},
	}
	for _, tt := range tests {
		got, ok := tt.r.Prefix()
		if ok != (got != IPPrefix{}) {
			t.Errorf("for %v, Prefix() results inconsistent: %v, %v", tt.r, got, ok)
		}
		if got != tt.want {
			t.Errorf("for %v, Prefix = %v; want %v", tt.r, got, tt.want)
		}
	}

	allocs := int(testing.AllocsPerRun(1000, func() {
		tt := tests[0]
		if _, ok := tt.r.Prefix(); !ok {
			t.Fatal("expected okay")
		}
	}))
	if allocs != 0 {
		t.Errorf("allocs = %v", allocs)
	}
}

func BenchmarkIPRangePrefix(b *testing.B) {
	b.ReportAllocs()
	r := IPRange{mustIP("10.0.0.0"), mustIP("10.0.0.255")}
	for i := 0; i < b.N; i++ {
		if _, ok := r.Prefix(); !ok {
			b.Fatal("expected a prefix")
		}
	}
}

var nextPriorTests = []struct {
	ip    IP
	next  IP
	prior IP
}{
	{mustIP("10.0.0.1"), mustIP("10.0.0.2"), mustIP("10.0.0.0")},
	{mustIP("10.0.0.255"), mustIP("10.0.1.0"), mustIP("10.0.0.254")},
	{mustIP("127.0.0.1"), mustIP("127.0.0.2"), mustIP("127.0.0.0")},
	{mustIP("254.255.255.255"), mustIP("255.0.0.0"), mustIP("254.255.255.254")},
	{mustIP("255.255.255.255"), IP{}, mustIP("255.255.255.254")},
	{mustIP("0.0.0.0"), mustIP("0.0.0.1"), IP{}},
	{mustIP("::"), mustIP("::1"), IP{}},
	{mustIP("::%x"), mustIP("::1%x"), IP{}},
	{mustIP("::1"), mustIP("::2"), mustIP("::")},
	{mustIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), IP{}, mustIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe")},
}

func TestIPNextPrior(t *testing.T) {
	doNextPrior(t)

	for _, ip := range []IP{
		mustIP("0.0.0.0"),
		mustIP("::"),
	} {
		got := ip.Prior()
		if !got.IsZero() {
			t.Errorf("IP(%v).Prior = %v; want zero", ip, got)
		}
	}

	var allFF [16]byte
	for i := range allFF {
		allFF[i] = 0xff
	}

	for _, ip := range []IP{
		mustIP("255.255.255.255"),
		IPv6Raw(allFF),
	} {
		got := ip.Next()
		if !got.IsZero() {
			t.Errorf("IP(%v).Next = %v; want zero", ip, got)
		}
	}
}

func BenchmarkIPNextPrior(b *testing.B) {
	for i := 0; i < b.N; i++ {
		doNextPrior(b)
	}
}

func doNextPrior(t testing.TB) {
	for _, tt := range nextPriorTests {
		gnext, gprior := tt.ip.Next(), tt.ip.Prior()
		if gnext != tt.next {
			t.Errorf("IP(%v).Next = %v; want %v", tt.ip, gnext, tt.next)
		}
		if gprior != tt.prior {
			t.Errorf("IP(%v).Prior = %v; want %v", tt.ip, gprior, tt.prior)
		}
		if !tt.ip.Next().IsZero() && tt.ip.Next().Prior() != tt.ip {
			t.Errorf("IP(%v).Next.Prior = %v; want %v", tt.ip, tt.ip.Next().Prior(), tt.ip)
		}
		if !tt.ip.Prior().IsZero() && tt.ip.Prior().Next() != tt.ip {
			t.Errorf("IP(%v).Prior.Next = %v; want %v", tt.ip, tt.ip.Prior().Next(), tt.ip)
		}
	}
}

func TestIPBitLen(t *testing.T) {
	tests := []struct {
		ip   IP
		want uint8
	}{
		{IP{}, 0},
		{mustIP("0.0.0.0"), 32},
		{mustIP("10.0.0.1"), 32},
		{mustIP("::"), 128},
		{mustIP("fed0::1"), 128},
		{mustIP("::ffff:10.0.0.1"), 128},
	}
	for _, tt := range tests {
		got := tt.ip.BitLen()
		if got != tt.want {
			t.Errorf("BitLen(%v) = %d; want %d", tt.ip, got, tt.want)
		}
	}
}

func TestIPPrefixContains(t *testing.T) {
	tests := []struct {
		ipp  IPPrefix
		ip   IP
		want bool
	}{
		{mustIPPrefix("9.8.7.6/0"), mustIP("9.8.7.6"), true},
		{mustIPPrefix("9.8.7.6/16"), mustIP("9.8.7.6"), true},
		{mustIPPrefix("9.8.7.6/16"), mustIP("9.8.6.4"), true},
		{mustIPPrefix("9.8.7.6/16"), mustIP("9.9.7.6"), false},
		{mustIPPrefix("9.8.7.6/32"), mustIP("9.8.7.6"), true},
		{mustIPPrefix("9.8.7.6/32"), mustIP("9.8.7.7"), false},
		{mustIPPrefix("9.8.7.6/32"), mustIP("9.8.7.7"), false},
		{mustIPPrefix("::1/0"), mustIP("::1"), true},
		{mustIPPrefix("::1/0"), mustIP("::2"), true},
		{mustIPPrefix("::1/127"), mustIP("::1"), true},
		{mustIPPrefix("::1/127"), mustIP("::2"), false},
		{mustIPPrefix("::1/128"), mustIP("::1"), true},
		{mustIPPrefix("::1/127"), mustIP("::2"), false},
		// zones support
		{mustIPPrefix("::1%a/128"), mustIP("::1"), true},    // prefix zones are stripped...
		{mustIPPrefix("::1%a/128"), mustIP("::1%a"), false}, // but ip zones are not
		// invalid IP
		{mustIPPrefix("::1/0"), IP{}, false},
		{mustIPPrefix("1.2.3.4/0"), IP{}, false},
		// invalid IPPrefix
		{IPPrefix{mustIP("::1"), 129}, mustIP("::1"), false},
		{IPPrefix{mustIP("1.2.3.4"), 33}, mustIP("1.2.3.4"), false},
		{IPPrefix{IP{}, 0}, mustIP("1.2.3.4"), false},
		{IPPrefix{IP{}, 32}, mustIP("1.2.3.4"), false},
		{IPPrefix{IP{}, 128}, mustIP("::1"), false},
		// wrong IP family
		{mustIPPrefix("::1/0"), mustIP("1.2.3.4"), false},
		{mustIPPrefix("1.2.3.4/0"), mustIP("::1"), false},
	}
	for _, tt := range tests {
		got := tt.ipp.Contains(tt.ip)
		if got != tt.want {
			t.Errorf("(%v).Contains(%v) = %v want %v", tt.ipp, tt.ip, got, tt.want)
		}
	}
}

func TestIPv6Accessor(t *testing.T) {
	var a [16]byte
	for i := range a {
		a[i] = uint8(i) + 1
	}
	ip := IPv6Raw(a)
	for i := range a {
		if got, want := ip.v6(uint8(i)), uint8(i)+1; got != want {
			t.Errorf("v6(%v) = %v; want %v", i, got, want)
		}
	}
}

// Sink variables are here to force the compiler to not elide
// seemingly useless work in benchmarks and allocation tests. If you
// were to just `_ = foo()` within a test function, the compiler could
// correctly deduce that foo() does nothing and doesn't need to be
// called. By writing results to a global variable, we hide that fact
// from the compiler and force it to keep the code under test.
var (
	sinkIP            IP
	sinkStdIP         net.IP
	sinkIPPort        IPPort
	sinkIPPrefix      IPPrefix
	sinkIPPrefixSlice []IPPrefix
	sinkIPRange       IPRange
	sinkInternValue   *intern.Value
	sinkIP16          [16]byte
	sinkIP4           [4]byte
	sinkBool          bool
	sinkString        string
	sinkBytes         []byte
	sinkUDPAddr       = &net.UDPAddr{IP: make(net.IP, 0, 16)}
)

func TestNoAllocs(t *testing.T) {
	// Wrappers that panic on error, to prove that our alloc-free
	// methods are returning successfully.
	panicIP := func(ip IP, err error) IP {
		if err != nil {
			panic(err)
		}
		return ip
	}
	panicIPOK := func(ip IP, ok bool) IP {
		if !ok {
			panic("not ok")
		}
		return ip
	}
	panicPfx := func(pfx IPPrefix, err error) IPPrefix {
		if err != nil {
			panic(err)
		}
		return pfx
	}
	panicPfxOK := func(pfx IPPrefix, ok bool) IPPrefix {
		if !ok {
			panic("not ok")
		}
		return pfx
	}
	panicIPP := func(ipp IPPort, err error) IPPort {
		if err != nil {
			panic(err)
		}
		return ipp
	}
	panicIPPOK := func(ipp IPPort, ok bool) IPPort {
		if !ok {
			panic("not ok")
		}
		return ipp
	}

	test := func(name string, f func()) {
		t.Run(name, func(t *testing.T) {
			n := testing.AllocsPerRun(1000, f)
			if n != 0 {
				t.Fatalf("allocs = %d; want 0", int(n))
			}
		})
	}

	// IP constructors
	test("IPv4", func() { sinkIP = IPv4(1, 2, 3, 4) })
	test("IPFrom4", func() { sinkIP = IPFrom4([4]byte{1, 2, 3, 4}) })
	test("IPv6", func() { sinkIP = IPv6Raw([16]byte{}) })
	test("IPFrom16", func() { sinkIP = IPFrom16([16]byte{15: 1}) })
	test("ParseIP/4", func() { sinkIP = panicIP(ParseIP("1.2.3.4")) })
	test("ParseIP/6", func() { sinkIP = panicIP(ParseIP("::1")) })
	test("MustParseIP", func() { sinkIP = MustParseIP("1.2.3.4") })
	test("FromStdIP", func() { sinkIP = panicIPOK(FromStdIP(net.IP([]byte{1, 2, 3, 4}))) })
	test("FromStdIPRaw", func() { sinkIP = panicIPOK(FromStdIPRaw(net.IP([]byte{1, 2, 3, 4}))) })
	test("IPv6LinkLocalAllNodes", func() { sinkIP = IPv6LinkLocalAllNodes() })
	test("IPv6Unspecified", func() { sinkIP = IPv6Unspecified() })

	// IP methods
	test("IP.IsZero", func() { sinkBool = MustParseIP("1.2.3.4").IsZero() })
	test("IP.BitLen", func() { sinkBool = MustParseIP("1.2.3.4").BitLen() == 8 })
	test("IP.Zone/4", func() { sinkBool = MustParseIP("1.2.3.4").Zone() == "" })
	test("IP.Zone/6", func() { sinkBool = MustParseIP("fe80::1").Zone() == "" })
	test("IP.Zone/6zone", func() { sinkBool = MustParseIP("fe80::1%zone").Zone() == "" })
	test("IP.Compare", func() {
		a := MustParseIP("1.2.3.4")
		b := MustParseIP("2.3.4.5")
		sinkBool = a.Compare(b) == 0
	})
	test("IP.Less", func() {
		a := MustParseIP("1.2.3.4")
		b := MustParseIP("2.3.4.5")
		sinkBool = a.Less(b)
	})
	test("IP.Is4", func() { sinkBool = MustParseIP("1.2.3.4").Is4() })
	test("IP.Is6", func() { sinkBool = MustParseIP("fe80::1").Is6() })
	test("IP.Is4in6", func() { sinkBool = MustParseIP("fe80::1").Is4in6() })
	test("IP.Unmap", func() { sinkIP = MustParseIP("ffff::2.3.4.5").Unmap() })
	test("IP.WithZone", func() { sinkIP = MustParseIP("fe80::1").WithZone("") })
	test("IP.IsGlobalUnicast", func() { sinkBool = MustParseIP("2001:db8::1").IsGlobalUnicast() })
	test("IP.IsInterfaceLocalMulticast", func() { sinkBool = MustParseIP("fe80::1").IsInterfaceLocalMulticast() })
	test("IP.IsLinkLocalMulticast", func() { sinkBool = MustParseIP("fe80::1").IsLinkLocalMulticast() })
	test("IP.IsLinkLocalUnicast", func() { sinkBool = MustParseIP("fe80::1").IsLinkLocalUnicast() })
	test("IP.IsLoopback", func() { sinkBool = MustParseIP("fe80::1").IsLoopback() })
	test("IP.IsMulticast", func() { sinkBool = MustParseIP("fe80::1").IsMulticast() })
	test("IP.IsPrivate", func() { sinkBool = MustParseIP("fd00::1").IsPrivate() })
	test("IP.IsUnspecified", func() { sinkBool = IPv6Unspecified().IsUnspecified() })
	test("IP.Prefix/4", func() { sinkIPPrefix = panicPfx(MustParseIP("1.2.3.4").Prefix(20)) })
	test("IP.Prefix/6", func() { sinkIPPrefix = panicPfx(MustParseIP("fe80::1").Prefix(64)) })
	test("IP.As16", func() { sinkIP16 = MustParseIP("1.2.3.4").As16() })
	test("IP.As4", func() { sinkIP4 = MustParseIP("1.2.3.4").As4() })
	test("IP.Next", func() { sinkIP = MustParseIP("1.2.3.4").Next() })
	test("IP.Prior", func() { sinkIP = MustParseIP("1.2.3.4").Prior() })

	// IPPort constructors
	test("IPPortFrom", func() { sinkIPPort = IPPortFrom(IPv4(1, 2, 3, 4), 22) })
	test("ParseIPPort", func() { sinkIPPort = panicIPP(ParseIPPort("[::1]:1234")) })
	test("MustParseIPPort", func() { sinkIPPort = MustParseIPPort("[::1]:1234") })
	test("FromStdAddr", func() {
		std := net.IP{1, 2, 3, 4}
		sinkIPPort = panicIPPOK(FromStdAddr(std, 5678, ""))
	})

	// IPPort methods
	test("UDPAddrAt", func() { sinkUDPAddr = MustParseIPPort("1.2.3.4:1234").UDPAddrAt(sinkUDPAddr) })

	// IPPrefix constructors
	test("IPPrefixFrom", func() { sinkIPPrefix = IPPrefixFrom(IPv4(1, 2, 3, 4), 32) })
	test("ParseIPPrefix/4", func() { sinkIPPrefix = panicPfx(ParseIPPrefix("1.2.3.4/20")) })
	test("ParseIPPrefix/6", func() { sinkIPPrefix = panicPfx(ParseIPPrefix("fe80::1/64")) })
	test("MustParseIPPrefix", func() { sinkIPPrefix = MustParseIPPrefix("1.2.3.4/20") })
	test("FromStdIPNet", func() {
		std := &net.IPNet{
			IP:   net.IP{1, 2, 3, 4},
			Mask: net.IPMask{255, 255, 0, 0},
		}
		sinkIPPrefix = panicPfxOK(FromStdIPNet(std))
	})

	// IPPrefix methods
	test("IPPrefix.Contains", func() { sinkBool = MustParseIPPrefix("1.2.3.0/24").Contains(MustParseIP("1.2.3.4")) })
	test("IPPrefix.Overlaps", func() {
		a, b := MustParseIPPrefix("1.2.3.0/24"), MustParseIPPrefix("1.2.0.0/16")
		sinkBool = a.Overlaps(b)
	})
	test("IPPrefix.IsZero", func() { sinkBool = MustParseIPPrefix("1.2.0.0/16").IsZero() })
	test("IPPrefix.IsSingleIP", func() { sinkBool = MustParseIPPrefix("1.2.3.4/32").IsSingleIP() })
	test("IPPRefix.Masked", func() { sinkIPPrefix = MustParseIPPrefix("1.2.3.4/16").Masked() })
	test("IPPRefix.Range", func() { sinkIPRange = MustParseIPPrefix("1.2.3.4/16").Range() })

	// IPRange constructors
	test("IPRangeFrom", func() { sinkIPRange = IPRangeFrom(IPv4(1, 2, 3, 4), IPv4(4, 3, 2, 1)) })
	test("ParseIPRange", func() { sinkIPRange = MustParseIPRange("1.2.3.0-1.2.4.150") })

	// IPRange methods
	test("IPRange.IsZero", func() { sinkBool = MustParseIPRange("1.2.3.0-1.2.4.150").IsZero() })
	test("IPRange.IsValid", func() { sinkBool = MustParseIPRange("1.2.3.0-1.2.4.150").IsValid() })
	test("IPRange.Overlaps", func() {
		a := MustParseIPRange("1.2.3.0-1.2.3.150")
		b := MustParseIPRange("1.2.4.0-1.2.4.255")
		sinkBool = a.Overlaps(b)
	})
	test("IPRange.Prefix", func() {
		a := MustParseIPRange("1.2.3.0-1.2.3.255")
		sinkIPPrefix = panicPfxOK(a.Prefix())
	})
}

func TestIPPrefixString(t *testing.T) {
	tests := []struct {
		ipp  IPPrefix
		want string
	}{
		{IPPrefix{}, "zero IPPrefix"},
		{IPPrefixFrom(IP{}, 8), "invalid IPPrefix"},
		{IPPrefixFrom(MustParseIP("1.2.3.4"), 88), "invalid IPPrefix"},
	}

	for _, tt := range tests {
		if got := tt.ipp.String(); got != tt.want {
			t.Errorf("(%#v).String() = %q want %q", tt.ipp, got, tt.want)
		}
	}
}

func TestInvalidIPPortString(t *testing.T) {
	tests := []struct {
		ipp  IPPort
		want string
	}{
		{IPPort{}, "invalid IPPort"},
		{IPPortFrom(IP{}, 80), "invalid IPPort"},
	}

	for _, tt := range tests {
		if got := tt.ipp.String(); got != tt.want {
			t.Errorf("(%#v).String() = %q want %q", tt.ipp, got, tt.want)
		}
	}
}

func TestMethodParity(t *testing.T) {
	// Collect all method names for each type.
	methods := make(map[string][]reflect.Type)
	allTypes := []reflect.Type{
		reflect.TypeOf((*IP)(nil)),
		reflect.TypeOf((*IPPort)(nil)),
		reflect.TypeOf((*IPPrefix)(nil)),
		reflect.TypeOf((*IPRange)(nil)),
	}
	for _, typ := range allTypes {
		for i := 0; i < typ.NumMethod(); i++ {
			name := typ.Method(i).Name
			methods[name] = append(methods[name], typ)
		}
	}

	// Check whether sufficiently common methods exist on all types.
	ignoreList := map[string]string{
		"Valid": "method is deprecated",
	}
	for name, types := range methods {
		if _, ignore := ignoreList[name]; ignore {
			continue // method is ignored for parity check
		}
		if !(len(allTypes)/2 < len(types) && len(types) < len(allTypes)) {
			continue // either too unique or all types already have that method
		}
		for _, typ := range allTypes {
			if _, ok := typ.MethodByName(name); ok {
				continue // this type already has this method
			}
			t.Errorf("%v.%v is missing", typ.Elem().Name(), name)
		}
	}
}
