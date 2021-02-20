// Copyright 2020 The Inet.Af AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package netaddr_test

import (
	"fmt"

	"inet.af/netaddr"
)

func ExampleIPSet() {
	var b netaddr.IPSetBuilder

	b.AddPrefix(netaddr.MustParseIPPrefix("10.0.0.0/8"))
	b.RemovePrefix(netaddr.MustParseIPPrefix("10.0.0.0/16"))

	b.AddRange(netaddr.IPRange{
		From: netaddr.MustParseIP("fed0::0400"),
		To:   netaddr.MustParseIP("fed0::04ff"),
	})

	s := b.IPSet()

	fmt.Println("Ranges:")
	for _, r := range s.Ranges() {
		fmt.Printf("  %s - %s\n", r.From, r.To)
	}

	fmt.Println("Prefixes:")
	for _, p := range s.Prefixes() {
		fmt.Printf("  %s\n", p)
	}
	// Output:
	// Ranges:
	//   10.1.0.0 - 10.255.255.255
	//   fed0::400 - fed0::4ff
	// Prefixes:
	//   10.1.0.0/16
	//   10.2.0.0/15
	//   10.4.0.0/14
	//   10.8.0.0/13
	//   10.16.0.0/12
	//   10.32.0.0/11
	//   10.64.0.0/10
	//   10.128.0.0/9
	//   fed0::400/120
}
