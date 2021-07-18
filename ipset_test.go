// Copyright 2020 The Inet.Af AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package netaddr

import (
	"bytes"
	"fmt"
	"log"
	"math/rand"
	"reflect"
	"testing"
)

func buildIPSet(b *IPSetBuilder) *IPSet {
	ret, err := b.IPSet()
	if err != nil {
		panic(err)
	}
	return ret
}

func TestIPSet(t *testing.T) {
	tests := []struct {
		name         string
		f            func(s *IPSetBuilder)
		wantRanges   []IPRange
		wantPrefixes []IPPrefix      // non-nil to test
		wantContains map[string]bool // optional non-exhaustive IPs to test for in resulting set
	}{
		{
			name: "mix_family",
			f: func(s *IPSetBuilder) {
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
			f: func(s *IPSetBuilder) {
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
			f: func(s *IPSetBuilder) {
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
			f: func(s *IPSetBuilder) {
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
			f: func(s *IPSetBuilder) {
				s.AddPrefix(mustIPPrefix("10.0.0.0/8"))
				s.AddPrefix(mustIPPrefix("10.0.0.0/8"))
			},
			wantRanges: []IPRange{
				{mustIP("10.0.0.0"), mustIP("10.255.255.255")},
			},
		},
		{
			name: "add_dup_subet",
			f: func(s *IPSetBuilder) {
				s.AddPrefix(mustIPPrefix("10.0.0.0/8"))
				s.AddPrefix(mustIPPrefix("10.0.0.0/16"))
			},
			wantRanges: []IPRange{
				{mustIP("10.0.0.0"), mustIP("10.255.255.255")},
			},
		},
		{
			name: "add_remove_add",
			f: func(s *IPSetBuilder) {
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
			f: func(s *IPSetBuilder) {
				s.RemovePrefix(mustIPPrefix("1.2.3.4/32")) // no-op
				s.AddPrefix(mustIPPrefix("1.2.3.4/32"))
			},
			wantRanges: []IPRange{
				{mustIP("1.2.3.4"), mustIP("1.2.3.4")},
			},
		},
		{
			name: "remove_end_on_add_start",
			f: func(s *IPSetBuilder) {
				s.AddRange(IPRange{mustIP("0.0.0.38"), mustIP("0.0.0.177")})
				s.RemoveRange(IPRange{mustIP("0.0.0.18"), mustIP("0.0.0.38")})
			},
			wantRanges: []IPRange{
				{mustIP("0.0.0.39"), mustIP("0.0.0.177")},
			},
		},
		{
			name: "fuzz_fail_2",
			f: func(s *IPSetBuilder) {
				s.AddRange(IPRange{mustIP("0.0.0.143"), mustIP("0.0.0.185")})
				s.AddRange(IPRange{mustIP("0.0.0.84"), mustIP("0.0.0.174")})
				s.AddRange(IPRange{mustIP("0.0.0.51"), mustIP("0.0.0.61")})
				s.RemoveRange(IPRange{mustIP("0.0.0.66"), mustIP("0.0.0.146")})
				s.AddRange(IPRange{mustIP("0.0.0.22"), mustIP("0.0.0.207")})
				s.RemoveRange(IPRange{mustIP("0.0.0.198"), mustIP("0.0.0.203")})
				s.RemoveRange(IPRange{mustIP("0.0.0.23"), mustIP("0.0.0.69")})
				s.AddRange(IPRange{mustIP("0.0.0.64"), mustIP("0.0.0.105")})
				s.AddRange(IPRange{mustIP("0.0.0.151"), mustIP("0.0.0.203")})
				s.AddRange(IPRange{mustIP("0.0.0.138"), mustIP("0.0.0.160")})
				s.RemoveRange(IPRange{mustIP("0.0.0.64"), mustIP("0.0.0.161")})
			},
			wantRanges: []IPRange{
				{mustIP("0.0.0.22"), mustIP("0.0.0.22")},
				{mustIP("0.0.0.162"), mustIP("0.0.0.207")},
			},
			wantContains: map[string]bool{
				"0.0.0.22": true,
			},
		},
		{
			name: "single_ips",
			f: func(s *IPSetBuilder) {
				s.Add(mustIP("10.0.0.0"))
				s.Add(mustIP("10.0.0.1"))
				s.Add(mustIP("10.0.0.2"))
				s.Add(mustIP("10.0.0.3"))
				s.Add(mustIP("10.0.0.4"))
				s.Remove(mustIP("10.0.0.4"))
				s.Add(mustIP("10.0.0.255"))
			},
			wantRanges: []IPRange{
				{mustIP("10.0.0.0"), mustIP("10.0.0.3")},
				{mustIP("10.0.0.255"), mustIP("10.0.0.255")},
			},
			wantPrefixes: pxv("10.0.0.0/30", "10.0.0.255/32"),
		},
		{
			// regression test for a bug where Ranges returned invalid IPRanges.
			name: "single_ip_removal",
			f: func(s *IPSetBuilder) {
				s.Add(mustIP("10.0.0.0"))
				s.Add(mustIP("10.0.0.1"))
				s.Add(mustIP("10.0.0.2"))
				s.Add(mustIP("10.0.0.3"))
				s.Add(mustIP("10.0.0.4"))
				s.Remove(mustIP("10.0.0.4"))
			},
			wantRanges: []IPRange{
				{mustIP("10.0.0.0"), mustIP("10.0.0.3")},
			},
			wantPrefixes: pxv("10.0.0.0/30"),
		},
		{
			name: "invert_empty",
			f: func(s *IPSetBuilder) {
				s.Complement()
			},
			wantRanges: []IPRange{
				{mustIP("0.0.0.0"), mustIP("255.255.255.255")},
				{mustIP("::"), mustIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
			},
			wantPrefixes: pxv("0.0.0.0/0", "::/0"),
		},
		{
			name: "invert_full",
			f: func(s *IPSetBuilder) {
				s.AddPrefix(mustIPPrefix("0.0.0.0/0"))
				s.AddPrefix(mustIPPrefix("::/0"))
				s.Complement()
			},
			wantRanges:   []IPRange{},
			wantPrefixes: pxv(),
		},
		{
			name: "invert_partial",
			f: func(s *IPSetBuilder) {
				s.AddRange(IPRange{mustIP("1.1.1.1"), mustIP("2.2.2.2")})
				s.Add(mustIP("3.3.3.3"))
				s.AddPrefix(mustIPPrefix("4.4.4.0/24"))
				s.Add(mustIP("1::1"))
				s.Complement()
			},
			wantRanges: []IPRange{
				{mustIP("0.0.0.0"), mustIP("1.1.1.0")},
				{mustIP("2.2.2.3"), mustIP("3.3.3.2")},
				{mustIP("3.3.3.4"), mustIP("4.4.3.255")},
				{mustIP("4.4.5.0"), mustIP("255.255.255.255")},
				{mustIP("::"), mustIP("1::")},
				{mustIP("1::2"), mustIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
			},
		},
		{
			name: "intersect",
			f: func(s *IPSetBuilder) {
				var t IPSetBuilder
				t.AddRange(IPRange{mustIP("2.2.2.2"), mustIP("3.3.3.3")})

				s.AddRange(IPRange{mustIP("1.1.1.1"), mustIP("4.4.4.4")})
				s.Intersect(buildIPSet(&t))
			},
			wantRanges: []IPRange{
				{mustIP("2.2.2.2"), mustIP("3.3.3.3")},
			},
		},
		{
			name: "intersect_disjoint",
			f: func(s *IPSetBuilder) {
				var t IPSetBuilder
				t.AddRange(IPRange{mustIP("1.1.1.1"), mustIP("2.2.2.2")})

				s.AddRange(IPRange{mustIP("3.3.3.3"), mustIP("4.4.4.4")})
				s.Intersect(buildIPSet(&t))
			},
			wantRanges: []IPRange{},
		},
		{
			name: "intersect_partial",
			f: func(s *IPSetBuilder) {
				var t IPSetBuilder
				t.AddRange(IPRange{mustIP("1.1.1.1"), mustIP("3.3.3.3")})

				s.AddRange(IPRange{mustIP("2.2.2.2"), mustIP("4.4.4.4")})
				s.Intersect(buildIPSet(&t))
			},
			wantRanges: []IPRange{
				{mustIP("2.2.2.2"), mustIP("3.3.3.3")},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			debugf = t.Logf
			defer func() { debugf = discardf }()
			var build IPSetBuilder
			tt.f(&build)
			s := buildIPSet(&build)
			got := s.Ranges()
			t.Run("ranges", func(t *testing.T) {
				for _, v := range got {
					if !v.IsValid() {
						t.Errorf("invalid IPRange in result: %s -> %s", v.From(), v.To())
					}
				}
				if reflect.DeepEqual(got, tt.wantRanges) {
					return
				}
				t.Error("failed. got:\n")
				for _, v := range got {
					t.Errorf("  %s -> %s", v.From(), v.To())
				}
				t.Error("want:\n")
				for _, v := range tt.wantRanges {
					t.Errorf("  %s -> %s", v.From(), v.To())
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
			if len(tt.wantContains) > 0 {
				for ipStr, want := range tt.wantContains {
					got := s.Contains(mustIP(ipStr))
					if got != want {
						t.Errorf("Contains(%q) = %v; want %v", s, got, want)
					}
				}
			}
		})
	}
}

func TestIPSetRemoveFreePrefix(t *testing.T) {
	pfx := mustIPPrefix
	tests := []struct {
		name         string
		f            func(s *IPSetBuilder)
		b            uint8
		wantPrefix   IPPrefix
		wantPrefixes []IPPrefix
		wantOK       bool
	}{
		{
			name: "cut in half",
			f: func(s *IPSetBuilder) {
				s.AddPrefix(pfx("10.0.0.0/8"))
			},
			b:            9,
			wantPrefix:   pfx("10.0.0.0/9"),
			wantPrefixes: pxv("10.128.0.0/9"),
			wantOK:       true,
		},
		{
			name: "on prefix left",
			f: func(s *IPSetBuilder) {
				s.AddPrefix(pfx("10.0.0.0/8"))
				s.RemovePrefix(pfx("10.0.0.0/9"))
			},
			b:            9,
			wantPrefix:   pfx("10.128.0.0/9"),
			wantPrefixes: []IPPrefix{},
			wantOK:       true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			debugf = t.Logf
			var build IPSetBuilder
			tt.f(&build)
			s := buildIPSet(&build)
			gotPrefix, gotSet, ok := s.RemoveFreePrefix(tt.b)
			if ok != tt.wantOK {
				t.Errorf("extractPrefix() ok = %t, wantOK %t", ok, tt.wantOK)
				return
			}
			if !reflect.DeepEqual(gotPrefix, tt.wantPrefix) {
				t.Errorf("extractPrefix() = %v, want %v", gotPrefix, tt.wantPrefix)
			}
			if !reflect.DeepEqual(gotSet.Prefixes(), tt.wantPrefixes) {
				t.Errorf("extractPrefix() = %v, want %v", gotSet.Prefixes(), tt.wantPrefixes)
			}
		})
	}
}

func mustIPSet(ranges ...string) *IPSet {
	var ret IPSetBuilder
	for _, r := range ranges {
		ipr, err := ParseIPRange(r[1:])
		if err != nil {
			panic(err)
		}
		switch r[0] {
		case '+':
			ret.AddRange(ipr)
		case '-':
			ret.RemoveRange(ipr)
		default:
			panic(fmt.Sprintf("unknown command %q", r[0]))
		}
	}
	return buildIPSet(&ret)
}

func TestIPSetOverlaps(t *testing.T) {
	tests := []struct {
		a, b *IPSet
		want bool
	}{
		{
			mustIPSet(),
			mustIPSet(),
			false,
		},
		{
			mustIPSet("+10.0.0.0-10.0.0.5"),
			mustIPSet("+10.0.0.0-10.0.0.5"),
			true, // exact match
		},
		{
			mustIPSet("+10.0.0.0-10.0.0.5"),
			mustIPSet("+10.0.0.5-10.0.0.10"),
			true, // overlap on edge
		},
		{
			mustIPSet("+10.0.0.0-10.0.0.5"),
			mustIPSet("+10.0.0.3-10.0.0.7"),
			true, // overlap in middle
		},
		{
			mustIPSet("+10.0.0.0-10.0.0.5"),
			mustIPSet("+10.0.0.2-10.0.0.3"),
			true, // one inside other
		},
		{
			mustIPSet("+10.0.0.0-10.0.0.5", "+10.1.0.0-10.1.0.5"),
			mustIPSet("+10.1.0.1-10.1.0.2"),
			true, // overlap in non-first
		},
		{
			mustIPSet("+10.0.0.0-10.0.0.10", "-10.0.0.5-10.0.0.10"),
			mustIPSet("+10.0.0.7-10.0.0.8"),
			false, // removal cancels overlap
		},
		{
			mustIPSet("+10.0.0.0-10.0.0.10", "-10.0.0.5-10.0.0.10", "+10.0.0.5-10.0.0.10"),
			mustIPSet("+10.0.0.7-10.0.0.8"),
			true, // removal+readd restores overlap
		},
	}

	for _, test := range tests {
		got := test.a.Overlaps(test.b)
		if got != test.want {
			t.Errorf("(%s).Overlaps(%s) = %v, want %v", test.a, test.b, got, test.want)
		}
		got = test.b.Overlaps(test.a)
		if got != test.want {
			t.Errorf("(%s).Overlaps(%s) = %v, want %v", test.b, test.a, got, test.want)
		}
	}
}

func TestIPSetContains(t *testing.T) {
	var build IPSetBuilder
	build.AddPrefix(mustIPPrefix("10.0.0.0/8"))
	build.AddPrefix(mustIPPrefix("1.2.3.4/32"))
	build.AddPrefix(mustIPPrefix("fc00::/7"))
	s := buildIPSet(&build)

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

		{"fd00::%a", false},
		{"fd00::1%a", false},
	}
	for _, tt := range tests {
		got := s.Contains(mustIP(tt.ip))
		if got != tt.want {
			t.Errorf("contains(%q) = %v; want %v", tt.ip, got, tt.want)
		}
	}
}

func TestIPSetFuzz(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		doIPSetFuzz(t, 100)
	} else {
		doIPSetFuzz(t, 5000)
	}
}

func BenchmarkIPSetFuzz(b *testing.B) {
	b.ReportAllocs()
	doIPSetFuzz(b, b.N)
}

func doIPSetFuzz(t testing.TB, iters int) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	debugf = logger.Printf
	defer func() { debugf = discardf }()
	for i := 0; i < iters; i++ {
		buf.Reset()
		steps, set, wantContains := newRandomIPSet()
		for b, want := range wantContains {
			ip := IPv4(0, 0, 0, uint8(b))
			got := set.Contains(ip)
			if got != want {
				t.Fatalf("for steps %q, contains(%v) = %v; want %v\n%s", steps, ip, got, want, buf.Bytes())
			}
		}
	}
}

func newRandomIPSet() (steps []string, s *IPSet, wantContains [256]bool) {
	b := new(IPSetBuilder)
	nstep := 2 + rand.Intn(10)
	for i := 0; i < nstep; i++ {
		op := rand.Intn(2)
		ip1 := uint8(rand.Intn(256))
		ip2 := uint8(rand.Intn(256))
		if ip2 < ip1 {
			ip1, ip2 = ip2, ip1
		}
		var v bool
		switch op {
		case 0:
			steps = append(steps, fmt.Sprintf("add 0.0.0.%d-0.0.0.%d", ip1, ip2))
			b.AddRange(IPRangeFrom(IPv4(0, 0, 0, ip1), IPv4(0, 0, 0, ip2)))
			v = true
		case 1:
			steps = append(steps, fmt.Sprintf("remove 0.0.0.%d-0.0.0.%d", ip1, ip2))
			b.RemoveRange(IPRangeFrom(IPv4(0, 0, 0, ip1), IPv4(0, 0, 0, ip2)))
		}
		for i := ip1; i <= ip2; i++ {
			wantContains[i] = v
			if i == ip2 {
				break
			}
		}
	}
	s = buildIPSet(b)
	return
}

// TestIPSetRanges tests IPSet.Ranges against 64k
// patterns of sets of ranges, checking the real implementation
// against the test's separate implementation.
//
// For each of uint16 pattern, each set bit is treated as an IP that
// should be in the set's resultant Ranges.
func TestIPSetRanges(t *testing.T) {
	t.Parallel()
	upper := 0x0fff
	if *long {
		upper = 0xffff
	}
	for pat := 0; pat <= upper; pat++ {
		var build IPSetBuilder
		var from, to IP
		ranges := make([]IPRange, 0)
		flush := func() {
			r := IPRangeFrom(from, to)
			build.AddRange(r)
			ranges = append(ranges, r)
			from, to = IP{}, IP{}
		}
		for b := uint16(0); b < 16; b++ {
			if uint16(pat)&(1<<b) != 0 {
				ip := IPv4(1, 0, 0, uint8(b))
				to = ip
				if from.IsZero() {
					from = ip
				}
				continue
			}
			if !from.IsZero() {
				flush()
			}
		}
		if !from.IsZero() {
			flush()
		}
		got := buildIPSet(&build).Ranges()
		if !reflect.DeepEqual(got, ranges) {
			t.Errorf("for %016b: got %v; want %v", pat, got, ranges)
		}
	}
}

func TestIPSetRangesStress(t *testing.T) {
	t.Parallel()
	n := 50
	if testing.Short() {
		n /= 10
	} else if *long {
		n = 500
	}
	const numIPs = 1 << 16 // we test lower 16 bits only
	randRange := func() (a, b int, r IPRange) {
		a, b = rand.Intn(numIPs), rand.Intn(numIPs)
		if a > b {
			a, b = b, a
		}
		from := IPv4(0, 0, uint8(a>>8), uint8(a))
		to := IPv4(0, 0, uint8(b>>8), uint8(b))
		return a, b, IPRangeFrom(from, to)
	}
	for i := 0; i < n; i++ {
		var build IPSetBuilder
		var want [numIPs]bool
		// Add some ranges
		for i := 0; i < 1+rand.Intn(2); i++ {
			a, b, r := randRange()
			for i := a; i <= b; i++ {
				want[i] = true
			}
			build.AddRange(r)
		}
		// Remove some ranges
		for i := 0; i < rand.Intn(3); i++ {
			a, b, r := randRange()
			for i := a; i <= b; i++ {
				want[i] = false
			}
			build.RemoveRange(r)
		}
		ranges := buildIPSet(&build).Ranges()

		// Make sure no ranges are adjacent or overlapping
		for i, r := range ranges {
			if i == 0 {
				continue
			}
			if ranges[i-1].To().Compare(r.From()) != -1 {
				t.Fatalf("overlapping ranges: %v", ranges)
			}
		}

		// Copy the ranges back to a new set before using
		// ContainsFunc, in case the ContainsFunc implementation
		// changes in the future to not use Ranges itself:
		var build2 IPSetBuilder
		for _, r := range ranges {
			build2.AddRange(r)
		}
		s2 := buildIPSet(&build2)
		for i, want := range want {
			if got := s2.Contains(IPv4(0, 0, uint8(i>>8), uint8(i))); got != want {
				t.Fatal("failed")
			}
		}
	}
}

func TestIPSetEqual(t *testing.T) {
	a := new(IPSetBuilder)
	b := new(IPSetBuilder)

	assertEqual := func(want bool) {
		t.Helper()
		if got := buildIPSet(a).Equal(buildIPSet(b)); got != want {
			t.Errorf("%v.Equal(%v) = %v want %v", a, b, got, want)
		}
	}

	a.Add(MustParseIP("1.1.1.0"))
	a.Add(MustParseIP("1.1.1.1"))
	a.Add(MustParseIP("1.1.1.2"))
	b.AddPrefix(MustParseIPPrefix("1.1.1.0/31"))
	b.Add(MustParseIP("1.1.1.2"))
	assertEqual(true)

	a.RemoveSet(buildIPSet(a))
	assertEqual(false)
	b.RemoveSet(buildIPSet(b))
	assertEqual(true)

	a.Add(MustParseIP("1.1.1.0"))
	a.Add(MustParseIP("1.1.1.1"))
	a.Add(MustParseIP("1.1.1.2"))

	b.AddPrefix(MustParseIPPrefix("1.1.1.0/30"))
	b.Remove(MustParseIP("1.1.1.3"))
	assertEqual(true)
}
