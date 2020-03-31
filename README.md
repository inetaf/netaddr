# netaddr

## Warning

This package is a work in progress. Don't use it yet.

## What

This is a package containing a new IP address type for Go.

See its docs: https://godoc.org/inet.af/netaddr

## Motivation

* https://github.com/golang/go/issues/18804 ("net: reconsider representation of IP")
* https://github.com/golang/go/issues/18757 ("net: ParseIP should return an error, like other Parse functions")
* https://github.com/golang/go/issues/37921 ("net: Unable to reliably distinguish IPv4-mapped-IPv6 addresses from regular IPv4 addresses")
* merges net.IPAddr and net.IP (which the Go net package is a little torn between for legacy reasons)
* ...
* TODO: finish this list
