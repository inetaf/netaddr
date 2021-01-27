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

// toInOnly updates s to clear s.out, by merging any s.out into s.in.
func (s *IPSet) toInOnly() {
	if len(s.out) > 0 {
		s.in = s.Ranges()
		s.out = nil
	}
}

// Clone returns a copy of s that shares no memory with s.
func (s *IPSet) Clone() *IPSet {
	return &IPSet{
		in: s.Ranges(),
	}
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
	s.toInOnly()
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

// Complement updates s to contain the complement of its current
// contents.
func (s *IPSet) Complement() {
	s.toInOnly()
	s.out = s.in
	s.in = []IPRange{
		IPPrefix{IP: IPv4(0, 0, 0, 0), Bits: 0}.Range(),
		IPPrefix{IP: IPv6Unspecified(), Bits: 0}.Range(),
	}
}

// Intersect updates s to the set intersection of s and b.
func (s *IPSet) Intersect(b *IPSet) {
	b = b.Clone()
	b.Complement()
	s.RemoveSet(b)
}

func discardf(format string, args ...interface{}) {}

// debugf is reassigned by tests.
var debugf = discardf

// Ranges returns the minimum and sorted set of IP
// ranges that covers s.
func (s *IPSet) Ranges() []IPRange {
	const debug = false
	if debug {
		debugf("ranges start in=%v out=%v", s.in, s.out)
	}
	in, ok := mergeIPRanges(s.in)
	if !ok {
		return nil
	}
	out, ok := mergeIPRanges(s.out)
	if !ok {
		return nil
	}
	if debug {
		debugf("ranges sort  in=%v out=%v", in, out)
	}

	// in and out are sorted in ascending range order, and have no
	// overlaps within each other. We can run a merge of the two lists
	// in one pass.

	ret := make([]IPRange, 0, len(in))
	for len(in) > 0 && len(out) > 0 {
		rin, rout := in[0], out[0]
		if debug {
			debugf("step in=%v out=%v", rin, rout)
		}

		switch {
		case !rout.Valid() || !rin.Valid():
			// mergeIPRanges should have prevented invalid ranges from
			// sneaking in.
			panic("invalid IPRanges during Ranges merge")
		case rout.entirelyBefore(rin):
			// "out" is entirely before "in".
			//
			//    out         in
			// f-------t   f-------t
			out = out[1:]
			if debug {
				debugf("out before in; drop out")
			}
		case rin.entirelyBefore(rout):
			// "in" is entirely before "out".
			//
			//    in         out
			// f------t   f-------t
			ret = append(ret, rin)
			in = in[1:]
			if debug {
				debugf("in before out; append in")
				debugf("ret=%v", ret)
			}
		case rin.coveredBy(rout):
			// "out" entirely covers "in".
			//
			//       out
			// f-------------t
			//    f------t
			//       in
			in = in[1:]
			if debug {
				debugf("in inside out; drop in")
			}
		case rout.inMiddleOf(rin):
			// "in" entirely covers "out".
			//
			//       in
			// f-------------t
			//    f------t
			//       out
			ret = append(ret, IPRange{From: rin.From, To: rout.From.Prior()})
			// Adjust in[0], not ir, because we want to consider the
			// mutated range on the next iteration.
			in[0].From = rout.To.Next()
			out = out[1:]
			if debug {
				debugf("out inside in; split in, append first in, drop out, adjust second in")
				debugf("ret=%v", ret)
			}
		case rout.overlapsStartOf(rin):
			// "out" overlaps start of "in".
			//
			//   out
			// f------t
			//    f------t
			//       in
			in[0].From = rout.To.Next()
			// Can't move ir onto ret yet, another later out might
			// trim it further. Just discard or and continue.
			out = out[1:]
			if debug {
				debugf("out cuts start of in; adjust in, drop out")
			}
		case rout.overlapsEndOf(rin):
			// "out" overlaps end of "in".
			//
			//           out
			//        f------t
			//    f------t
			//       in
			ret = append(ret, IPRange{From: rin.From, To: rout.From.Prior()})
			in = in[1:]
			if debug {
				debugf("merge out cuts end of in; append shortened in")
				debugf("ret=%v", ret)
			}
		default:
			// The above should account for all combinations of in and
			// out overlapping, but insert a panic to be sure.
			panic("unexpected additional overlap scenario")
		}
	}
	if len(in) > 0 {
		// Ran out of removals before the end of in.
		ret = append(ret, in...)
		if debug {
			debugf("ret=%v", ret)
		}
	}

	// TODO: possibly update s.in and s.out, if #110 supports that.

	return ret
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
