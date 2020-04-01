// Copyright 2020 The Inet.Af AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package netaddr

import (
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"sort"
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
		})
	}
}

func TestIPProperties(t *testing.T) {
	// TODO: expand test with more Is* property checks.

	var (
		nilIP IP

		unicast4     = mustIP("192.0.2.1")
		unicast6     = mustIP("2001:db::1")
		unicastZone6 = mustIP("fe80::1%eth0")

		multicast4     = mustIP("224.0.0.1")
		multicast6     = mustIP("ff02::1")
		multicastZone6 = mustIP("ff02::1%eth0")
	)

	tests := []struct {
		name      string
		ip        IP
		multicast bool
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			multicast := tt.ip.IsMulticast()
			if multicast != tt.multicast {
				t.Errorf("IsMulticast = %v; want %v", multicast, tt.multicast)
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
		{mustIP("::fffe:c000:0280"), false, mustIP("::fffe:c000:0280")},
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

func mustIP(s string) IP {
	ip, err := ParseIP(s)
	if err != nil {
		panic(err)
	}

	return ip
}
