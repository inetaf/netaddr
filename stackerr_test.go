// Copyright 2021 The Inet.Af AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package netaddr_test

import (
	"strings"
	"testing"

	"inet.af/netaddr"
)

// The tests for stacktrace errors is in its own file,
// so that the line number munging that we do doesn't
// break line numbers for other tests.

func TestStacktraceErr(t *testing.T) {
	b := new(netaddr.IPSetBuilder)
//line ipp.go:1
	b.AddPrefix(netaddr.IPPrefix{})
//line r.go:2
	b.AddRange(netaddr.IPRange{})
	_, err := b.IPSet()
	got := err.Error()
	for _, want := range []string{"ipp.go:1", "r.go:2"} {
		if !strings.Contains(got, want) {
			t.Errorf("error should contain %q, got %q", want, got)
		}
	}
}
