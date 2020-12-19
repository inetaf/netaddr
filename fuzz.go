// Copyright 2020 The Inet.Af AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build gofuzz

package netaddr

func Fuzz(b []byte) int {
	s := string(b)

	ip, err := ParseIP(s)
	if err == nil {
		// There's no guarantee that ip.String() will match s.
		// But a round trip the other direction ought to succeed.
		ip2, err := ParseIP(ip.String())
		if err != nil {
			panic(err)
		}
		if ip2 != ip {
			panic("ip round trip identity failure")
		}
	}

	port, err := ParseIPPort(s)
	if err == nil {
		port2, err := ParseIPPort(port.String())
		if err != nil {
			panic(err)
		}
		if port2 != port {
			panic("IPPort round trip identity failure")
		}
	}

	pref, err := ParseIPPrefix(s)
	if err == nil {
		pref2, err := ParseIPPrefix(pref.String())
		if err != nil {
			panic(err)
		}
		if pref2 != pref {
			panic("IPPrefix round trip identity failure")
		}
	}

	return 0
}
