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
)

func TestBridgeDetect(t *testing.T) {
	srv, cleanup := testSetup(t)
	defer cleanup()

	links, nets, cleanup2 := testNetnsPair(t)
	defer cleanup2()

	br := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{
			Name: "br0",
		},
	}
	if err := netlink.LinkAdd(br); err != nil {
		t.Fatal(err)
	}
	defer func() {
		netlink.LinkDel(br)
	}()

	if err := netlink.LinkSetMaster(links[0], br); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetMaster(links[1], br); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(br); err != nil {
		t.Fatal(err)
	}

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
