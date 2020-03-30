// Copyright 2020 The Inet.Af AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package netaddr

import "testing"

func TestParseString(t *testing.T) {
	tests := []string{
		"1.2.3.4",
		"0.0.0.0",
		"::1",
		"fe80::1cc0:3e8c:119f:c2e1%ens18",
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
