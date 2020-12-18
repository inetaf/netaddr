// Copyright 2020 The Inet.Af AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !go1.19

package netaddr

import (
	"runtime"
	"sync"
	"unsafe"
)

// zone is the IPv6 zone and its generation count to prevent the finalizer
// from deleting weak references from the uniqZone map.
type zone struct {
	// name is the IPv6 zone.
	// It is immutable.
	name string

	// gen is guarded by zmu and is incremented whenever this zone
	// is returned.
	gen int64
}

var (
	z0    = (*zone)(nil)
	z4    = new(zone)
	z6noz = new(zone)
)

// zmu guards uniqZone, a weakref map of *zones by zoneName.
// It also guards the gen field of all zones.
var (
	zmu      sync.Mutex
	uniqZone = map[string]uintptr{} // zone name to its uintptr(*zone)
)

// internZone returns an interned zone for zoneName.
//
// We intern zones to guarantee that two zone pointers are equal
// iff their names are equal, so that IPs can be compared, used as map keys, etc.
//
// Interning is simple if you don't require that unused zones be garbage collectable.
// But we do require that; we don't want to be DOS vector.
// We do this by using a uintptr to hide our zone pointer from the garbage collector,
// and using a finalizer to eliminate our zone pointer when no other code is using it.
// (The checkptr runtime check prevents exactly these kinds of shenanigans; we disable it.)
//
// The obvious implementation of this is to use a map[string]uintptr,
// and set up a finalizer to delete from the map.
// Unfortunately, that contains a logical race.
// The finalizer can start concurrently with a new request
// to look up a zone with no other references to it.
// The new zone lookup creates a new reference to an existing (almost-GC-able) zone.
// The finalizer then continues to run, deleting the zone from the map.
// Future zone lookups will create a new zone, breaking the comparability invariant.
//
// The finalizer fundamentally needs to know that no other
// references have been created since this finalizer was set up.
// There is no external synchronization that can provide that.
// Instead, every time we create a new zone reference, we set a new finalizer.
// That finalizer knows the latest zone reference at the time that it was created;
// that is the gen (generation) field in type zone.
// When the finalizer runs, if its generation differs from the current zone generation,
// another reference must have been created in the interim,
// so it should not delete the zone from the map.
// Another, later, finalizer will take care of that.
// The zone generation field is protected by zmu, providing a consistent view.
//
// @josharian has a mild lingering concern about this approach.
// It is possible to for the runtime to concurrently decide it needs to _execute_ a finalizer and
// also _remove_ the need for that finalizer to run, because a new reference has appeared.
// It is possible that this could cause a data race in the runtime.
// This is not a normal thing to have happen; it requires unsafe hiding of a pointer in a uintptr.
// It thus might not be tested for or protected against in the runtime.
// Hopefully this will not prove to be a problem in practice.
//
// @ianlancetaylor commented in https://github.com/golang/go/issues/41303#issuecomment-717401656
// that it is possible to implement weak references in terms of finalizers without unsafe.
// Unfortunately, the approach he outlined does not work here, for two reasons.
// First, there is no way to construct a strong pointer out of a weak pointer;
// our map stores weak pointers, but we must return strong pointers to callers.
// Second, and more fundamentally, we must return not just _a_ strong pointer to callers,
// but _the same_ strong pointer to callers.
// In order to return _the same_ strong pointer to callers, we must track it,
// which is exactly what we cannot do with strong pointers.
//
// The current approach will fail if Go ever adopts a moving GC.
//
// See https://github.com/inetaf/netaddr/issues/53 for more discussion.
//
//go:nocheckptr
func internZone(zoneName string) *zone {
	zmu.Lock()
	defer zmu.Unlock()

	addr, ok := uniqZone[zoneName]
	var z *zone
	if ok {
		z = (*zone)((unsafe.Pointer)(addr))
	} else {
		z = &zone{name: zoneName}
		uniqZone[zoneName] = uintptr(unsafe.Pointer(z))
	}
	z.gen++
	curGen := z.gen

	if curGen > 1 {
		// Need to clear finalizer before changing it, else the runtime throws.
		// See https://groups.google.com/g/golang-dev/c/2c8suS1_840.
		runtime.SetFinalizer(z, nil)
	}
	runtime.SetFinalizer(z, func(z *zone) {
		zmu.Lock()
		defer zmu.Unlock()
		if z.gen != curGen {
			// Lost the race. Somebody is still using this zone.
			return
		}
		delete(uniqZone, z.name)
	})
	return z
}
