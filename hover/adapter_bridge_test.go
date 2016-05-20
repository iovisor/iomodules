// Copyright 2016 PLUMgrid
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

package hover

import (
	"os/exec"
	"sync"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

func testBridgeSimpleSetup(t *testing.T, nsPrefix string, br *netlink.Bridge) (
	*netlink.Bridge, []*netlink.Veth, []netns.NsHandle, func()) {
	links, nets, cleanup := testNetnsPair(t, nsPrefix)

	if br == nil {
		br = &netlink.Bridge{
			LinkAttrs: netlink.LinkAttrs{
				Name: "br0",
			},
		}
		if err := netlink.LinkAdd(br); err != nil {
			cleanup()
			t.Fatal(err)
		}
	}

	cleanup2 := func() {
		netlink.LinkDel(br)
		cleanup()
	}

	if err := netlink.LinkSetMaster(links[0], br); err != nil {
		cleanup2()
		t.Fatal(err)
	}
	if err := netlink.LinkSetMaster(links[1], br); err != nil {
		cleanup2()
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(br); err != nil {
		cleanup2()
		t.Fatal(err)
	}
	return br, links, nets, cleanup2
}

func TestBridgeDetect(t *testing.T) {
	srv, cleanup := testSetup(t)
	defer cleanup()

	br, _, nets, cleanup2 := testBridgeSimpleSetup(t, "ns", nil)
	defer cleanup2()

	testOne(t, testCase{
		url:    srv.URL + "/modules/b:" + br.Attrs().Name,
		method: "GET",
	}, nil)

	var wg sync.WaitGroup
	wg.Add(1)
	go RunInNs(nets[0], func() error {
		defer wg.Done()
		out, err := exec.Command("ping", "-c", "1", "10.10.1.2").Output()
		if err != nil {
			t.Error(string(out), err)
		}
		return nil
	})
	wg.Wait()
}

func TestBridgePolicy(t *testing.T) {
	srv, cleanup := testSetup(t)
	defer cleanup()

	br, _, nets, cleanup2 := testBridgeSimpleSetup(t, "ns", nil)
	defer cleanup2()

	testOne(t, testCase{
		url:    srv.URL + "/modules/b:" + br.Attrs().Name,
		method: "GET",
	}, nil)

	var t1 moduleEntry
	testOne(t, testCase{
		url:  srv.URL + "/modules/",
		body: wrapCodePolicy(t, policyC, []string{"b:" + br.Attrs().Name}),
	}, &t1)

	var wg sync.WaitGroup
	wg.Add(1)
	go RunInNs(nets[0], func() error {
		defer wg.Done()
		out, err := exec.Command("ping", "-c", "1", "10.10.1.2").Output()
		if err != nil {
			t.Error(string(out), err)
		}
		return nil
	})
	wg.Wait()

	var c1, c2 AdapterTablePair
	testOne(t, testCase{
		url:    srv.URL + "/modules/" + t1.Id + "/tables/counters/entries/0x0",
		method: "GET",
	}, &c1)
	if c1.Key != "0x0" || c1.Value == "0x0" {
		t.Fatalf("Expected counter 1 != 0, got %s", c1.Value)
	}
	testOne(t, testCase{
		url:    srv.URL + "/modules/" + t1.Id + "/tables/counters/entries/0x1",
		method: "GET",
	}, &c2)
	if c2.Key != "0x1" || c2.Value == "0x0" {
		t.Fatalf("Expected counter 1 != 0, got %s", c2.Value)
	}
}

func TestBridgePolicyLinkUpdate(t *testing.T) {
	srv, cleanup := testSetup(t)
	defer cleanup()

	br, _, _, cleanup2 := testBridgeSimpleSetup(t, "nsA", nil)
	defer cleanup2()

	testOne(t, testCase{
		url:    srv.URL + "/modules/b:" + br.Attrs().Name,
		method: "GET",
	}, nil)

	var t1 moduleEntry
	testOne(t, testCase{
		url:  srv.URL + "/modules/",
		body: wrapCodePolicy(t, policyC, []string{"b:" + br.Attrs().Name}),
	}, &t1)

	_, _, _, cleanup3 := testBridgeSimpleSetup(t, "nsB", br)
	defer cleanup3()
}
