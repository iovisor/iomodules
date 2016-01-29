// Copyright 2015 PLUMgrid
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// vim: set ts=8:sts=8:sw=8:noet

package hover

import (
	"runtime"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

var (
	initNs netns.NsHandle
)

func nsContext() func() {
	runtime.LockOSThread()
	return func() {
		if err := netns.Set(initNs); err != nil {
			panic(err)
		}
		runtime.UnlockOSThread()
	}
}

func init() {
	initNs, _ = netns.Get()
}

func RunInNs(fd netns.NsHandle, fn func() error) error {
	defer nsContext()()
	if err := netns.Set(fd); err != nil {
		return err
	}
	if err := fn(); err != nil {
		return err
	}
	return nil
}

// NewVeth creates a veth pair with the given name, moves the peer into the
// namespace n, then renames the peer to dstName and assigns the provided ip.
// If insideFn is not nil, also executes that function in the context of the
// given namespace.
func NewVeth(n netns.NsHandle, name, dstName, ip string, insideFn func(netlink.Link) error) (link *netlink.Veth, err error) {
	l := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
		},
		PeerName: name + "_",
	}
	if err = netlink.LinkAdd(l); err != nil {
		return
	}
	defer func() {
		if err != nil {
			netlink.LinkDel(l)
		}
	}()

	otherL, err := netlink.LinkByName(l.PeerName)
	if err != nil {
		return
	}
	if err = netlink.LinkSetNsFd(otherL, int(n)); err != nil {
		return
	}
	err = RunInNs(n, func() error {
		lo, err := netlink.LinkByName("lo")
		if err != nil {
			return err
		}
		err = netlink.LinkSetUp(lo)
		if err != nil {
			return err
		}
		l, err := netlink.LinkByName(name + "_")
		if err != nil {
			return err
		}
		if err = netlink.LinkSetName(l, dstName); err != nil {
			return err
		}
		l.Attrs().Name = dstName
		a, err := netlink.ParseIPNet(ip)
		if err != nil {
			return err
		}
		if err := netlink.AddrAdd(l, &netlink.Addr{IPNet: a}); err != nil {
			return err
		}
		if insideFn != nil {
			if err := insideFn(l); err != nil {
				return err
			}
		}
		if err = netlink.LinkSetUp(l); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return
	}
	if err = netlink.LinkSetUp(l); err != nil {
		return
	}
	link = l
	return
}

// NewNs creates a new network namespace and returns a handle to it. The caller
// is responsible for calling Close on the handle when done with it.
func NewNs() netns.NsHandle {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	origns, err := netns.Get()
	if err != nil {
		panic(err)
	}
	n, err := netns.New()
	if err != nil {
		panic(err)
	}
	if err := netns.Set(origns); err != nil {
		panic(err)
	}
	return n
}
