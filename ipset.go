// Copyright 2020 The Inet.Af AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package netaddr

import "sort"

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

// RemoveFreePrefix removes and returns a Prefix of length bits from the IPSet.
func (s *IPSet) RemoveFreePrefix(bitLen uint8) (p IPPrefix, ok bool) {
	prefixes := s.Prefixes()
	if len(prefixes) == 0 {
		return IPPrefix{}, false
	}

	var bestFit IPPrefix
	for _, prefix := range prefixes {
		if prefix.Bits > bitLen {
			continue
		}
		if bestFit.IP.IsZero() || prefix.Bits > bestFit.Bits {
			bestFit = prefix
			if bestFit.Bits == bitLen {
				// exact match, done.
				break
			}
		}
	}

	if bestFit.IP.IsZero() {
		return IPPrefix{}, false
	}

	prefix := IPPrefix{IP: bestFit.IP, Bits: bitLen}
	s.RemovePrefix(prefix)
	return prefix, true
}

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
// This is used by the implementation of IPSet.Ranges.
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
		return rv[i].contains(ip)
	}
}
