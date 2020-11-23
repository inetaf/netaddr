// Copyright 2020 The Inet.Af AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//lint:file-ignore U1000 allow unused code in tests for experiments.

package netaddr

import (
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestParseString(t *testing.T) {
	tests := []string{
		"1.2.3.4",
		"0.0.0.0",
		"::",
		"::1",
		"fe80::1cc0:3e8c:119f:c2e1%ens18",
		"::ffff:c000:1234",
	}
	for _, s := range tests {
		t.Run(s, func(t *testing.T) {
			ip, err := ParseIP(s)
			if err != nil {
				t.Fatal(err)
			}
			ip2, err := ParseIP(s)
			if err != nil {
				t.Fatal(err)
			}
			if ip != ip2 {
				t.Error("does not compare to self")
			}
			back := ip.String()
			if s != back {
				t.Errorf("String = %q; want %q", back, s)
			}
		})
	}
}

func TestIPMarshalUnmarshal(t *testing.T) {
	tests := []string{
		"",
		"1.2.3.4",
		"0.0.0.0",
		"::",
		"::1",
		"fe80::1cc0:3e8c:119f:c2e1%ens18",
		"::ffff:c000:1234",
	}

	for _, s := range tests {
		t.Run(s, func(t *testing.T) {
			// Ensure that JSON  (and by extension, text) marshaling is
			// sane by entering quoted input.
			orig := `"` + s + `"`

			var ip IP
			if err := json.Unmarshal([]byte(orig), &ip); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}

			ipb, err := json.Marshal(ip)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}

			back := string(ipb)
			if orig != back {
				t.Errorf("Marshal = %q; want %q", back, orig)
			}
		})
	}
}

func TestIPUnmarshalTextNonZero(t *testing.T) {
	ip := mustIP("::1")
	if err := ip.UnmarshalText([]byte("xxx")); err == nil {
		t.Fatal("unmarshaled into non-empty IP")
	}
}

func TestIPIPAddr(t *testing.T) {
	tests := []struct {
		name string
		ip   IP
		ipa  *net.IPAddr
	}{
		{
			name: "nil",
			ipa:  &net.IPAddr{},
		},
		{
			name: "v4Addr",
			ip:   mustIP("192.0.2.1"),
			ipa: &net.IPAddr{
				IP: net.IPv4(192, 0, 2, 1).To4(),
			},
		},
		{
			name: "v6Addr",
			ip:   mustIP("2001:db8::1"),
			ipa: &net.IPAddr{
				IP: net.ParseIP("2001:db8::1"),
			},
		},
		{
			name: "v6AddrZone",
			ip:   mustIP("fe80::1%eth0"),
			ipa: &net.IPAddr{
				IP:   net.ParseIP("fe80::1"),
				Zone: "eth0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.ip.IPAddr()
			if !reflect.DeepEqual(tt.ipa, got) {
				t.Errorf("IPAddr = %+v; want %+v", got, tt.ipa)
			}

			if got.Zone == "" && tt.ip != (IP{}) {
				back, ok := FromStdIP(got.IP)
				if !ok {
					t.Errorf("FromStdIP failed")
				} else if back != tt.ip {
					t.Errorf("FromStdIP = %v; want %v", back, tt.ip)
				}
			}
		})
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
			want: IP{v6Addr{15: 1}},
		},
		{
			name: "v6-from16",
			fn:   IPFrom16,
			in:   [...]byte{15: 1},
			want: IP{v6Addr{15: 1}},
		},
		{
			name: "v4-raw",
			fn:   IPv6Raw,
			in:   [...]byte{10: 0xff, 11: 0xff, 12: 1, 13: 2, 14: 3, 15: 4},
			want: IP{v6Addr{10: 0xff, 11: 0xff, 12: 1, 13: 2, 14: 3, 15: 4}},
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

		unicast4     = mustIP("192.0.2.1")
		unicast6     = mustIP("2001:db8::1")
		unicastZone6 = mustIP("2001:db8::1%eth0")

		multicast4     = mustIP("224.0.0.1")
		multicast6     = mustIP("ff02::1")
		multicastZone6 = mustIP("ff02::1%eth0")

		llu4     = mustIP("169.254.0.1")
		llu6     = mustIP("fe80::1")
		lluZone6 = mustIP("fe80::1%eth0")

		loopback4 = mustIP("127.0.0.1")
		loopback6 = mustIP("::1")
	)

	tests := []struct {
		name             string
		ip               IP
		multicast        bool
		linkLocalUnicast bool
		loopback         bool
	}{
		{
			name: "nil",
			ip:   nilIP,
		},
		{
			name: "unicast v4Addr",
			ip:   unicast4,
		},
		{
			name: "unicast v6Addr",
			ip:   unicast6,
		},
		{
			name: "unicast v6AddrZone",
			ip:   unicastZone6,
		},
		{
			name:      "multicast v4Addr",
			ip:        multicast4,
			multicast: true,
		},
		{
			name:      "multicast v6Addr",
			ip:        multicast6,
			multicast: true,
		},
		{
			name:      "multicast v6AddrZone",
			ip:        multicastZone6,
			multicast: true,
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			multicast := tt.ip.IsMulticast()
			if multicast != tt.multicast {
				t.Errorf("IsMulticast(%v) = %v; want %v", tt.ip, multicast, tt.multicast)
			}

			llu := tt.ip.IsLinkLocalUnicast()
			if llu != tt.linkLocalUnicast {
				t.Errorf("IsLinkLocalUnicast(%v) = %v; want %v", tt.ip, llu, tt.linkLocalUnicast)
			}

			lo := tt.ip.IsLoopback()
			if lo != tt.loopback {
				t.Errorf("IsLoopback(%v) = %v; want %v", tt.ip, lo, tt.loopback)
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
	want := `[invalid IP 1.2.3.4 8.8.8.8 ::1 ::1%foo ::2]`
	if got != want {
		t.Errorf("unexpected sort\n got: %s\nwant: %s\n", got, want)
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

func TestIPPrefixMarshalUnmarshal(t *testing.T) {
	tests := []string{
		"",
		"1.2.3.4/32",
		"0.0.0.0/0",
		"::/0",
		"::1/128",
		"fe80::1cc0:3e8c:119f:c2e1%ens18/128",
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
		prefix string
		ip     IP
	}{
		{
			prefix: "192.168.0.255/24",
			ip:     mustIP("192.168.0.0"),
		},
		{
			prefix: "2100::/3",
			ip:     mustIP("2000::"),
		},
	}
	for _, test := range tests {
		t.Run(test.prefix, func(t *testing.T) {
			prefix, err := ParseIPPrefix(test.prefix)
			if err != nil {
				t.Fatal(err)
			}
			prefix = prefix.Masked()
			if prefix.IP != test.ip {
				t.Errorf("IP=%s, want %s", prefix.IP, test.ip)
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
	}
	for _, test := range tests {
		t.Run(test.prefix, func(t *testing.T) {
			prefix, err := ParseIPPrefix(test.prefix)
			if err != nil {
				t.Fatal(err)
			}
			if prefix.IP != test.ip {
				t.Errorf("IP=%s, want %s", prefix.IP, test.ip)
			}
			if prefix.Bits != test.bits {
				t.Errorf("bits=%d, want %d", prefix.Bits, test.bits)
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
			if got := prefix.String(); got != test.prefix {
				t.Errorf("prefix.String()=%q, want %q", got, test.prefix)
			}
		})
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
			errstr: "unable to parse IP",
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

func TestParseIPError(t *testing.T) {
	tests := []struct {
		ip     string
		errstr string
	}{
		{
			ip: "localhost",
		},
		{
			ip: "500.0.0.1",
		},
		{
			ip: "::gggg%eth0",
		},
		{
			ip:     "fe80::1cc0:3e8c:119f:c2e1%",
			errstr: "missing zone",
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
	}
}

func TestUDPAddrAllocs(t *testing.T) {
	for _, ep := range []string{"1.2.3.4:1234", "[::1]:1234"} {
		ipp, err := ParseIPPort(ep)
		if err != nil {
			t.Fatalf("invalid %q", ep)
		}
		n := int(testing.AllocsPerRun(1000, func() {
			ua := ipp.UDPAddr()
			if ua.Port != int(ipp.Port) {
				t.Fatal("UDPAddr returned bogus result")
			}
			PutUDPAddr(ua)
		}))
		if n > 0 {
			t.Errorf("%d allocs for %q", n, ep)
		}
	}
}

func mustIP(s string) IP {
	ip, err := ParseIP(s)
	if err != nil {
		panic(err)
	}

	return ip
}

func mustIPs(strs ...string) []IP {
	var res []IP
	for _, s := range strs {
		res = append(res, mustIP(s))
	}
	return res
}

func mustIPPrefix(s string) IPPrefix {
	p, err := ParseIPPrefix(s)
	if err != nil {
		panic(err)
	}

	return p
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
	prefix := IPPrefix{
		IP:   IPv4(192, 168, 1, 0),
		Bits: 24,
	}
	ip := IPv4(192, 168, 1, 1)
	for i := 0; i < b.N; i++ {
		prefix.Contains(ip)
	}
}

func BenchmarkParseIPv4(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ParseIP("192.168.1.1")
	}
}

func BenchmarkParseIPv6(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ParseIP("fe80::1cc0:3e8c:119f:c2e1%ens18")
	}
}

func BenchmarkStdParseIPv4(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		net.ParseIP("192.168.1.1")
	}
}

func BenchmarkStdParseIPv6(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		net.ParseIP("fe80::1cc0:3e8c:119f:c2e1")
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
				tt.ip.Prefix(tt.bits)
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
		{IPPrefix{IP: IPv6Raw(mustIP("1.2.0.0").As16()), Bits: 16}, pfx("1.2.3.0/24"), false},
	}
	for i, tt := range tests {
		if got := tt.a.Overlaps(tt.b); got != tt.want {
			t.Errorf("%d. (%v).Overlaps(%v) = %v; want %v", i, tt.a, tt.b, got, tt.want)
		}
	}
}

func pxv(cidrStrs ...string) (out []IPPrefix) {
	for _, s := range cidrStrs {
		out = append(out, mustIPPrefix(s))
	}
	return
}

func TestIPRangeSet(t *testing.T) {
	tests := []struct {
		name         string
		f            func(s *IPRangeSet)
		wantRanges   []IPRange
		wantPrefixes []IPPrefix // non-nil to test
	}{
		{
			name: "mix_family",
			f: func(s *IPRangeSet) {
				s.AddPrefix(mustIPPrefix("10.0.0.0/8"))
				s.AddPrefix(mustIPPrefix("::/0"))
				s.RemovePrefix(mustIPPrefix("10.2.0.0/16"))
			},
			wantRanges: []IPRange{
				{mustIP("10.0.0.0"), mustIP("10.1.255.255")},
				{mustIP("10.3.0.0"), mustIP("10.255.255.255")},
				{mustIP("::"), mustIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
			},
		},
		{
			name: "merge_adjacent",
			f: func(s *IPRangeSet) {
				s.AddPrefix(mustIPPrefix("10.0.0.0/8"))
				s.AddPrefix(mustIPPrefix("11.0.0.0/8"))
			},
			wantRanges: []IPRange{
				{mustIP("10.0.0.0"), mustIP("11.255.255.255")},
			},
			wantPrefixes: pxv("10.0.0.0/7"),
		},
		{
			name: "remove_32",
			f: func(s *IPRangeSet) {
				s.AddPrefix(mustIPPrefix("10.0.0.0/8"))
				s.RemovePrefix(mustIPPrefix("10.1.2.3/32"))
			},
			wantRanges: []IPRange{
				{mustIP("10.0.0.0"), mustIP("10.1.2.2")},
				{mustIP("10.1.2.4"), mustIP("10.255.255.255")},
			},
			wantPrefixes: pxv(
				"10.0.0.0/16",
				"10.1.0.0/23",
				"10.1.2.0/31",
				"10.1.2.2/32",
				"10.1.2.4/30",
				"10.1.2.8/29",
				"10.1.2.16/28",
				"10.1.2.32/27",
				"10.1.2.64/26",
				"10.1.2.128/25",
				"10.1.3.0/24",
				"10.1.4.0/22",
				"10.1.8.0/21",
				"10.1.16.0/20",
				"10.1.32.0/19",
				"10.1.64.0/18",
				"10.1.128.0/17",
				"10.2.0.0/15",
				"10.4.0.0/14",
				"10.8.0.0/13",
				"10.16.0.0/12",
				"10.32.0.0/11",
				"10.64.0.0/10",
				"10.128.0.0/9",
			),
		},
		{
			name: "remove_32_and_first_16",
			f: func(s *IPRangeSet) {
				s.AddPrefix(mustIPPrefix("10.0.0.0/8"))
				s.RemovePrefix(mustIPPrefix("10.1.2.3/32"))
				s.RemovePrefix(mustIPPrefix("10.0.0.0/16"))
			},
			wantRanges: []IPRange{
				{mustIP("10.1.0.0"), mustIP("10.1.2.2")},
				{mustIP("10.1.2.4"), mustIP("10.255.255.255")},
			},
			wantPrefixes: pxv(
				"10.1.0.0/23",
				"10.1.2.0/31",
				"10.1.2.2/32",
				"10.1.2.4/30",
				"10.1.2.8/29",
				"10.1.2.16/28",
				"10.1.2.32/27",
				"10.1.2.64/26",
				"10.1.2.128/25",
				"10.1.3.0/24",
				"10.1.4.0/22",
				"10.1.8.0/21",
				"10.1.16.0/20",
				"10.1.32.0/19",
				"10.1.64.0/18",
				"10.1.128.0/17",
				"10.2.0.0/15",
				"10.4.0.0/14",
				"10.8.0.0/13",
				"10.16.0.0/12",
				"10.32.0.0/11",
				"10.64.0.0/10",
				"10.128.0.0/9",
			),
		},
		{
			name: "add_dup",
			f: func(s *IPRangeSet) {
				s.AddPrefix(mustIPPrefix("10.0.0.0/8"))
				s.AddPrefix(mustIPPrefix("10.0.0.0/8"))
			},
			wantRanges: []IPRange{
				{mustIP("10.0.0.0"), mustIP("10.255.255.255")},
			},
		},
		{
			name: "add_dup_subet",
			f: func(s *IPRangeSet) {
				s.AddPrefix(mustIPPrefix("10.0.0.0/8"))
				s.AddPrefix(mustIPPrefix("10.0.0.0/16"))
			},
			wantRanges: []IPRange{
				{mustIP("10.0.0.0"), mustIP("10.255.255.255")},
			},
		},
		{
			name: "add_remove_add",
			f: func(s *IPRangeSet) {
				s.AddPrefix(mustIPPrefix("10.0.0.0/8"))
				s.RemovePrefix(mustIPPrefix("10.1.2.3/32"))
				s.AddPrefix(mustIPPrefix("10.1.0.0/16")) // undoes prior line
			},
			wantRanges: []IPRange{
				{mustIP("10.0.0.0"), mustIP("10.255.255.255")},
			},
		},
		{
			name: "remove_then_add",
			f: func(s *IPRangeSet) {
				s.RemovePrefix(mustIPPrefix("1.2.3.4/32")) // no-op
				s.AddPrefix(mustIPPrefix("1.2.3.4/32"))
			},
			wantRanges: []IPRange{
				{mustIP("1.2.3.4"), mustIP("1.2.3.4")},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var s IPRangeSet
			tt.f(&s)
			got := s.Ranges()
			t.Run("ranges", func(t *testing.T) {
				if reflect.DeepEqual(got, tt.wantRanges) {
					return
				}
				t.Error("failed. got:\n")
				for _, v := range got {
					t.Errorf("  %s -> %s", v.From, v.To)
				}
				t.Error("want:\n")
				for _, v := range tt.wantRanges {
					t.Errorf("  %s -> %s", v.From, v.To)
				}
			})
			if tt.wantPrefixes != nil {
				t.Run("prefixes", func(t *testing.T) {
					got := s.Prefixes()
					if got == nil {
						got = []IPPrefix{}
					}
					if reflect.DeepEqual(got, tt.wantPrefixes) {
						return
					}
					t.Error("failed. got:\n")
					for _, v := range got {
						t.Errorf("  %v", v)
					}
					t.Error("want:\n")
					for _, v := range tt.wantPrefixes {
						t.Errorf("  %v", v)
					}
				})
			}
		})
	}
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
		r := IPRange{From: mustIP(tt.from), To: mustIP(tt.to)}
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

func TestIPNextPrior(t *testing.T) {
	tests := []struct {
		ip    IP
		next  IP
		prior IP
	}{
		{mustIP("10.0.0.1"), mustIP("10.0.0.2"), mustIP("10.0.0.0")},
		{mustIP("10.0.0.255"), mustIP("10.0.1.0"), mustIP("10.0.0.254")},
		{mustIP("254.255.255.255"), mustIP("255.0.0.0"), mustIP("254.255.255.254")},
		{mustIP("255.255.255.255"), IP{}, mustIP("255.255.255.254")},
		{mustIP("0.0.0.0"), mustIP("0.0.0.1"), IP{}},
		{mustIP("::"), mustIP("::1"), IP{}},
		{mustIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), IP{}, mustIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe")},
	}
	for _, tt := range tests {
		gnext, gprior := tt.ip.Next(), tt.ip.Prior()
		if gnext != tt.next {
			t.Errorf("IP(%v).Next = %v; want %v", tt.ip, gnext, tt.next)
		}
		if gprior != tt.prior {
			t.Errorf("IP(%v).Prior = %v; want %v", tt.ip, gprior, tt.prior)
		}
	}
}

func TestIPRangeSetContainsFunc(t *testing.T) {
	var s IPRangeSet
	s.AddPrefix(mustIPPrefix("10.0.0.0/8"))
	s.AddPrefix(mustIPPrefix("1.2.3.4/32"))
	s.AddPrefix(mustIPPrefix("fc00::/7"))
	contains := s.ContainsFunc()

	tests := []struct {
		ip   string
		want bool
	}{
		{"0.0.0.0", false},
		{"::", false},

		{"1.2.3.3", false},
		{"1.2.3.4", true},
		{"1.2.3.5", false},

		{"9.255.255.255", false},
		{"10.0.0.0", true},
		{"10.1.2.3", true},
		{"10.255.255.255", true},
		{"11.0.0.0", false},

		{"::", false},
		{"fc00::", true},
		{"fc00::1", true},
		{"fd00::1", true},
		{"ff00::1", false},
	}
	for _, tt := range tests {
		got := contains(mustIP(tt.ip))
		if got != tt.want {
			t.Errorf("contains(%q) = %v; want %v", tt.ip, got, tt.want)
		}
	}
}
