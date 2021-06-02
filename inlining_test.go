// Copyright 2020 The Inet.Af AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package netaddr

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestInlining(t *testing.T) {
	if v := runtime.Version(); strings.HasPrefix(v, "go1.14") ||
		strings.HasPrefix(v, "go1.13") ||
		strings.HasPrefix(v, "go1.12") ||
		strings.HasPrefix(v, "go1.11") {
		t.Skipf("skipping test on old Go version %q", v)
	}
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	t.Parallel()
	var exe string
	if runtime.GOOS == "windows" {
		exe = ".exe"
	}
	out, err := exec.Command(
		filepath.Join(runtime.GOROOT(), "bin", "go"+exe),
		"build",
		"--gcflags=-m",
		"inet.af/netaddr").CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v, %s", err, out)
	}
	got := map[string]bool{}
	regexp.MustCompile(` can inline (\S+)`).ReplaceAllFunc(out, func(match []byte) []byte {
		got[strings.TrimPrefix(string(match), " can inline ")] = true
		return nil
	})
	for _, want := range []string{
		"(*IPSetBuilder).Clone",
		"(*IPSet).Ranges",
		"(*uint128).halves",
		"IP.BitLen",
		"IP.hasZone",
		"IP.IPAddr",
		"IP.Is4",
		"IP.Is4in6",
		"IP.Is6",
		"IP.IsLoopback",
		"IP.IsMulticast",
		"IP.IsInterfaceLocalMulticast",
		"IP.IsZero",
		"IP.Less",
		"IP.lessOrEq",
		"IP.Next",
		"IP.Prior",
		"IP.Unmap",
		"IP.Zone",
		"IP.v4",
		"IP.v6",
		"IP.v6u16",
		"IP.withoutZone",
		"IPPort.IsZero",
		"IPPort.TCPAddr",
		"IPPort.UDPAddr",
		"IPPort.UDPAddrAt",
		"IPPortFrom",
		"IPPort.IP",
		"IPPort.Port",
		"IPPort.Valid",
		"IPPort.WithIP",
		"IPPort.WithPort",
		"IPPrefix.IsSingleIP",
		"IPPrefix.IsZero",
		"IPPrefix.Masked",
		"IPPrefix.Valid",
		"IPPrefixFrom",
		"IPPrefix.IP",
		"IPPrefix.Bits",
		"IPRange.Prefixes",
		"IPRange.prefixFrom128AndBits",
		"IPRange.prefixFrom128AndBits-fm",
		"IPRange.entirelyBefore",
		"IPRangeFrom",
		"IPRange.To",
		"IPRange.From",
		"IPv4",
		"IPFrom4",
		"IPv6LinkLocalAllNodes",
		"IPv6Unspecified",
		"MustParseIP",
		"MustParseIPPort",
		"MustParseIPPrefix",
		"appendDecimal",
		"appendHex",
		"discardf",
		"u64CommonPrefixLen",
		"uint128.addOne",
		"uint128.and",
		"uint128.bitsClearedFrom",
		"uint128.bitsSetFrom",
		"uint128.commonPrefixLen",
		"uint128.isZero",
		"uint128.not",
		"uint128.or",
		"uint128.subOne",
		"uint128.xor",
	} {
		if !got[want] {
			t.Errorf("%q is no longer inlinable", want)
			continue
		}
		delete(got, want)
	}
	for sym := range got {
		if strings.Contains(sym, ".func") {
			continue
		}
		t.Logf("not in expected set, but also inlinable: %q", sym)

	}
}
