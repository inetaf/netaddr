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
			want: IPPort{mustIP("1.2.3.4").Unmap(), 567},
		},
		{
			name: "v6",
			ua: &net.UDPAddr{
				IP:   net.ParseIP("::1"),
				Port: 567,
			},
			want: IPPort{mustIP("::1").Unmap(), 567},
		},
		{
			name: "v6zone",
			ua: &net.UDPAddr{
				IP:   net.ParseIP("::1"),
				Port: 567,
				Zone: "foo",
			},
			want: IPPort{mustIP("::1").Unmap().WithZone("foo"), 567},
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
	)

	tests := []struct {
		name             string
		ip               IP
		multicast        bool
		linkLocalUnicast bool
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
		})
	}
}

func TestLess(t *testing.T) {
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
	}
	for _, tt := range tests {
		got := tt.a.Less(tt.b)
		if got != tt.want {
			t.Errorf("Less(%s, %s) = %v; want %v", tt.a, tt.b, got, tt.want)
		}

		// Also check inverse.
		if got == tt.want && got {
			got2 := tt.b.Less(tt.a)
			if got2 {
				t.Errorf("Less(%s, %s) was correctly %v, but so was Less(%s, %s)", tt.a, tt.b, got, tt.b, tt.a)
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
			t.Errorf("is4in6(%q) = %v; want %v", tt.ip, got, tt.want)
		}
		u := tt.ip.Unmap()
		if u != tt.wantUnmap {
			t.Errorf("Unmap(%v) = %v; want %v", tt.ip, u, tt.wantUnmap)
		}
	}
}

func TestIPPrefix(t *testing.T) {
	tests := []struct {
		prefix      string
		ip          IP
		bits        uint8
		contains    []IP
		notContains []IP
	}{
		{
			prefix:      "192.168.0.0/24",
			ip:          mustIP("192.168.0.0"),
			bits:        24,
			contains:    mustIPs("192.168.0.1", "192.168.0.55"),
			notContains: mustIPs("192.168.1.1", "1.1.1.1"),
		},
		{
			prefix:      "192.168.1.1/32",
			ip:          mustIP("192.168.1.1"),
			bits:        32,
			contains:    mustIPs("192.168.1.1"),
			notContains: mustIPs("192.168.1.2"),
		},
		{
			prefix:      "2001:db8::/96",
			ip:          mustIP("2001:db8::"),
			bits:        96,
			contains:    mustIPs("2001:db8::aaaa:bbbb", "2001:db8::1"),
			notContains: mustIPs("2001:db8::1:aaaa:bbbb", "2001:db9::"),
		},
		{
			prefix:   "0.0.0.0/0",
			ip:       mustIP("0.0.0.0"),
			bits:     0,
			contains: mustIPs("192.168.0.1", "1.1.1.1"),
		},
		{
			prefix:   "::/0",
			ip:       mustIP("::"),
			bits:     0,
			contains: mustIPs("::1", "2001:db8::1"),
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
			errstr: "lookup 1.257.1.1: no such host", // TODO: improve ParseIP error
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
