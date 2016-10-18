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

package daemon

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync"
	"testing"
	_ "time"

	"github.com/vishvananda/netlink"

	"github.com/iovisor/iomodules/hover"
	"github.com/iovisor/iomodules/hover/api"
)

var (
	trivialC = `
static int handle_rx(void *pkt, struct metadata *md) {
	return RX_OK;
}
	`
	errorC = `
static int handle_rx(void *pkt, struct metadata *md) {
	*(volatile int*)0 = 0;
	return RX_OK;
}
`
	syntaxErrorC = `
static int handle_rx(void *pkt, struct metadata *md) {
	if () {}
	return RX_OK;
}
`

	redirectC = `
BPF_TABLE("array", int, int, redirect, 10);
static int handle_rx(void *pkt, struct metadata *md) {
	int in_ifc = md->in_ifc;
	int *out_ifc = redirect.lookup(&in_ifc);
	if (!out_ifc)
		return RX_DROP;
	pkt_redirect(pkt, md, *out_ifc);
	return RX_REDIRECT;
}
`

	policyC = `
BPF_TABLE("array", int, u64, counters, 2);
static void incr(int counter) {
	u64 *val = counters.lookup(&counter);
	if (val)
		++(*val);
}
static int handle_rx(void *pkt, struct metadata *md) {
	if (md->in_ifc == 1) // ingress
		incr(0);
	else if (md->in_ifc == 2) // egress
		incr(1);
	return RX_OK;
}
`
	moduleRedirectC = `
static int handle_rx(void *skb, struct metadata *md) {
	if (md->in_ifc == 1){
		bpf_trace_printk("pkt: 1 -> 2\n");
		pkt_redirect(skb,md,2);
		return RX_REDIRECT;
	}
	if (md->in_ifc == 2){
		bpf_trace_printk("pkt: 2 -> 1\n");
		pkt_redirect(skb,md,1);
		return RX_REDIRECT;
	}
	bpf_trace_printk("pkt: in_ifc %d -> DROP\n",md->in_ifc);
	return RX_DROP;
}
`
)

// wrapCode creates a reader object to encapsulate a program in json
func wrapCode(t *testing.T, body string, tags []string) io.Reader {
	return newCodeReader(t, body, "bpf/forward", "test", tags)
}

// wrapCode creates a reader object to encapsulate a program in json
func wrapCodePolicy(t *testing.T, body string, tags []string) io.Reader {
	return newCodeReader(t, body, "bpf/policy", "policy", tags)
}

func newCodeReader(t *testing.T, body string, modtype string, name string, tags []string) io.Reader {
	req := &api.ModuleBase{
		ModuleType:  modtype,
		DisplayName: name,
		Tags:        tags,
		Config: map[string]interface{}{
			"code": body,
		},
	}
	return testWrapObject(t, req)
}

func TestModuleCreate(t *testing.T) {
	srv, cleanup := testSetup(t)
	defer cleanup()

	testValues := []testCase{
		{
			url:  srv.URL + "/modules/",
			body: wrapCode(t, trivialC, []string{}),
		},
		{
			url:  srv.URL + "/modules/",
			body: wrapCode(t, errorC, []string{}),
			code: http.StatusBadRequest,
		},
		{
			url:  srv.URL + "/modules/",
			body: wrapCode(t, syntaxErrorC, []string{}),
			code: http.StatusBadRequest,
		},
	}
	for _, test := range testValues {
		testOne(t, test, nil)
	}
}

func TestModuleConnect(t *testing.T) {
	srv, cleanup := testSetup(t)
	defer cleanup()

	var t1, t2 api.Module
	testOne(t, testCase{
		url:  srv.URL + "/modules/",
		body: wrapCode(t, trivialC, []string{}),
	}, &t1)
	testOne(t, testCase{
		url:  srv.URL + "/modules/",
		body: wrapCode(t, trivialC, []string{}),
	}, &t2)
	l1 := testLinkModules(t, srv, t1.Id, t2.Id)
	testOne(t, testCase{
		url:    srv.URL + "/links/" + l1,
		method: "DELETE",
	}, nil)
}

func testSetTableEntry(t *testing.T, srv *httptest.Server, modId, tblName string, k, v interface{}) {
	testOne(t, testCase{
		url:  srv.URL + fmt.Sprintf("/modules/%s/tables/%s/entries/", modId, tblName),
		body: strings.NewReader(fmt.Sprintf(`{"key":"%v","value":"%v"}`, k, v)),
	}, nil)
}

func TestModuleRedirect(t *testing.T) {
	srv, cleanup := testSetup(t)
	defer cleanup()

	// ns1 <-> redir1 <-> redir2 <-> ns2
	links, nets, cleanup2 := testNetnsPair(t, "ns")
	defer cleanup2()

	var t1, t2 api.Module
	testOne(t, testCase{
		url:  srv.URL + "/modules/",
		body: wrapCode(t, redirectC, []string{}),
	}, &t1)

	testOne(t, testCase{
		url:  srv.URL + "/modules/",
		body: wrapCode(t, redirectC, []string{}),
	}, &t2)

	Info.Printf("module id = %s\n", t1.Id)
	l1 := testLinkModules(t, srv, t1.Id, "i:"+links[0].Name)
	testLinkModules(t, srv, t1.Id, t2.Id)
	testLinkModules(t, srv, "i:"+links[1].Name, t2.Id)

	testSetTableEntry(t, srv, t1.Id, "redirect", 1, 2)
	testSetTableEntry(t, srv, t1.Id, "redirect", 2, 1)
	testSetTableEntry(t, srv, t2.Id, "redirect", 1, 2)
	testSetTableEntry(t, srv, t2.Id, "redirect", 2, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go hover.RunInNs(nets[0], func() error {
		defer wg.Done()
		out, err := exec.Command("ping", "-c", "1", "10.10.1.2").Output()
		if err != nil {
			t.Error(string(out), err)
		}
		return nil
	})
	wg.Wait()

	testOne(t, testCase{
		url:    srv.URL + "/links/" + l1,
		method: "DELETE",
	}, nil)
}

//Create simple forwarding module
//connect the module to 2 ns (ns1,ns2)
//POST link1 ns1,module
//POST linl2 ns2,module
//DELETE link1
//DELETE link2
func TestLinkDelete(t *testing.T) {
	srv, cleanup := testSetup(t)
	defer cleanup()

	// ns1 <-> ModuleRedirect <-> ns2
	links, nets, cleanup2 := testNetnsPair(t, "ns")
	defer cleanup2()

	var t1 api.Module
	testOne(t, testCase{
		url:  srv.URL + "/modules/",
		body: wrapCode(t, moduleRedirectC, []string{}),
	}, &t1)

	Info.Printf("module id = %s\n", t1.Id)
	l1 := testLinkModules(t, srv, t1.Id, "i:"+links[0].Name)
	l2 := testLinkModules(t, srv, t1.Id, "i:"+links[1].Name)

	var wg sync.WaitGroup
	wg.Add(1)
	go hover.RunInNs(nets[0], func() error {
		defer wg.Done()
		out, err := exec.Command("ping", "-c", "1", "10.10.1.2").Output()
		if err != nil {
			t.Error(string(out), err)
		}
		return nil
	})
	wg.Wait()

	testOne(t, testCase{
		url:    srv.URL + "/links/" + l1,
		method: "DELETE",
	}, nil)

	testOne(t, testCase{
		url:    srv.URL + "/links/" + l2,
		method: "DELETE",
	}, nil)
}

//ns11 eth0 10.10.1.1/24
//ns12 eth0 10.10.1.2/24
//ns21 eth0 10.10.1.1/24
//ns22 eth0 10.10.1.2/24

//POST Module1
//Create ns11, ns12
//connect Module1 to ns11 ns12
//POST link1 ns11<->Module1
//POST linl2 ns12<->Module1
//test ping between ns11<->ns12
//DELETE link1

//POST Module2
//Create ns21, ns22
//POST link3 ns11<->Module2
//POST link4 ns22<->Module2
//Now ns11 and ns22 should be able to ping each other accordind to their configuration
//test ping between ns11<->ns22
//DELETE link3
//DELETE link4
func TestLinkInterfaceToOtherModule(t *testing.T) {
	srv, cleanup := testSetup(t)
	defer cleanup()

	//Create ns11, ns12
	Info.Printf("create ns11 eth0 10.10.1.1/24\n")
	Info.Printf("create ns12 eth0 10.10.1.2/24\n")
	links, nets, cleanup2 := testNetnsPair(t, "ns1")
	defer cleanup2()

	//POST Module1
	Info.Printf("/modules/ POST ModuleRedirect\n")
	var t1 api.Module
	testOne(t, testCase{
		url:  srv.URL + "/modules/",
		body: wrapCode(t, moduleRedirectC, []string{}),
	}, &t1)
	Info.Printf("module id = %s\n", t1.Id)

	//connect Module1 to ns11 ns12
	//POST link1 ns11<->Module1
	l1 := testLinkModules(t, srv, t1.Id, "i:"+links[0].Name)
	Info.Printf("/links/ POST from:%s to:%s --> id:%s  OK\n", t1.Id, "i:"+links[0].Name, l1)
	//POST linl2 ns12<->Module1
	l2 := testLinkModules(t, srv, t1.Id, "i:"+links[1].Name)
	Info.Printf("/links/ POST from:%s to:%s --> id:%s  OK\n", t1.Id, "i:"+links[1].Name, l2)

	//test ping between ns11<->ns12
	var wg sync.WaitGroup
	wg.Add(1)
	go hover.RunInNs(nets[0], func() error {
		defer wg.Done()
		//TODO add ping output
		out, err := exec.Command("ping", "-c", "1", "10.10.1.2").Output()
		if err != nil {
			t.Error(string(out), err)
		}
		return nil
	})
	wg.Wait()

	//DELETE link1
	testOne(t, testCase{
		url:    srv.URL + "/links/" + l1,
		method: "DELETE",
	}, nil)
	Info.Printf("/links/ DELETE link-id:%s  OK\n", l1)

	//END FIRST PART

	//Create ns21, ns22
	Info.Printf("create ns21 eth0 10.10.1.1/24\n")
	Info.Printf("create ns22 eth0 10.10.1.2/24\n")
	links_, _, cleanup2_ := testNetnsPair(t, "ns2")
	defer cleanup2_()

	//POST Module2
	Info.Printf("/modules/ POST ModuleRedirect\n")
	var t1_ api.Module
	testOne(t, testCase{
		url:  srv.URL + "/modules/",
		body: wrapCode(t, moduleRedirectC, []string{}),
	}, &t1_)
	Info.Printf("module id = %s\n", t1_.Id)

	//POST link3 ns11<->Module2
	l3 := testLinkModules(t, srv, t1_.Id, "i:"+links[0].Name)
	Info.Printf("/links/ POST from:%s to:%s --> id:%s  OK\n", t1_.Id, "i:"+links[0].Name, l3)
	//POST link4 ns22<->Module2
	l4 := testLinkModules(t, srv, t1_.Id, "i:"+links_[1].Name)
	Info.Printf("/links/ POST from:%s to:%s --> id:%s  OK\n", t1_.Id, "i:"+links_[1].Name, l4)

	//Now ns11 and ns22 should be able to ping each other accordind to their configuration
	//test ping between ns11<->ns22
	var wg_ sync.WaitGroup
	wg_.Add(1)
	go hover.RunInNs(nets[0], func() error {
		defer wg_.Done()
		// The arp cache contains a dirty entry, caused by
		// some intermediate state caused all the various
		// reconnections done above. This dirty entry would
		// fail the ping: remove it.
		out_, err_ := exec.Command("arp", "-d", "10.10.1.2").Output()
		if err_ != nil {
			t.Error(string(out_), err_)
		}

		out_, err_ = exec.Command("ping", "-c", "1", "10.10.1.2").Output()
		if err_ != nil {
			t.Error(string(out_), err_)
		}
		return nil
	})
	wg_.Wait()

	//DELETE link3
	testOne(t, testCase{
		url:    srv.URL + "/links/" + l3,
		method: "DELETE",
	}, nil)
	Info.Printf("/links/ DELETE link-id:%s  OK\n", l3)

	//DELETE link4
	testOne(t, testCase{
		url:    srv.URL + "/links/" + l4,
		method: "DELETE",
	}, nil)
	Info.Printf("/links/ DELETE link-id:%s  OK\n", l4)
}

type policyEntry struct {
	Id     string `json:"id"`
	Module string `json:"module"`
}

//I want to re-connect the same ports (ns1, ns2) to the same module
//after a previous disconnect
//Create simple forwarding module
//connect the module to 2 ns (ns1,ns2)
//POST link1 ns1,module
//POST linl2 ns2,module
//DELETE link1
//DELETE link2
//POST link1 ns1,module
//POST linl2 ns2,module
func TestReconnectToSameModule(t *testing.T) {
	srv, cleanup := testSetup(t)
	defer cleanup()

	// ns1 <-> ModuleRedirect <-> ns2
	links, nets, cleanup2 := testNetnsPair(t, "ns")
	defer cleanup2()

	var t1 api.Module
	testOne(t, testCase{
		url:  srv.URL + "/modules/",
		body: wrapCode(t, moduleRedirectC, []string{}),
	}, &t1)

	Info.Printf("module id = %s\n", t1.Id)
	l1 := testLinkModules(t, srv, t1.Id, "i:"+links[0].Name)
	l2 := testLinkModules(t, srv, t1.Id, "i:"+links[1].Name)

	var wg sync.WaitGroup
	wg.Add(1)
	go hover.RunInNs(nets[0], func() error {
		defer wg.Done()
		out, err := exec.Command("ping", "-c", "1", "10.10.1.2").Output()
		if err != nil {
			t.Error(string(out), err)
		}
		return nil
	})
	wg.Wait()

	testOne(t, testCase{
		url:    srv.URL + "/links/" + l1,
		method: "DELETE",
	}, nil)

	testOne(t, testCase{
		url:    srv.URL + "/links/" + l2,
		method: "DELETE",
	}, nil)

	testLinkModules(t, srv, t1.Id, "i:"+links[0].Name)
	testLinkModules(t, srv, t1.Id, "i:"+links[1].Name)
}

//I want to connect the same ports (ns1, ns2) to Module2
//after a previous disconnect from Module1
//POST Module1
//POST link1 ns1,module1
//POST linl2 ns2,module1
//DELETE link1
//DELETE link2
//POST Module2
//POST link3 ns1,module2
//POST linl4 ns2,module2
func TestReconnectToDifferentModule(t *testing.T) {
	srv, cleanup := testSetup(t)
	defer cleanup()

	links, nets, cleanup2 := testNetnsPair(t, "ns")
	defer cleanup2()

	var t1 api.Module
	testOne(t, testCase{
		url:  srv.URL + "/modules/",
		body: wrapCode(t, moduleRedirectC, []string{}),
	}, &t1)

	Info.Printf("module id = %s\n", t1.Id)
	l1 := testLinkModules(t, srv, t1.Id, "i:"+links[0].Name)
	l2 := testLinkModules(t, srv, t1.Id, "i:"+links[1].Name)

	var wg sync.WaitGroup
	wg.Add(1)
	go hover.RunInNs(nets[0], func() error {
		defer wg.Done()
		out, err := exec.Command("ping", "-c", "1", "10.10.1.2").Output()
		if err != nil {
			t.Error(string(out), err)
		}
		return nil
	})
	wg.Wait()

	testOne(t, testCase{
		url:    srv.URL + "/links/" + l1,
		method: "DELETE",
	}, nil)

	testOne(t, testCase{
		url:    srv.URL + "/links/" + l2,
		method: "DELETE",
	}, nil)

	//POST Module2
	var t1_ api.Module
	testOne(t, testCase{
		url:  srv.URL + "/modules/",
		body: wrapCode(t, moduleRedirectC, []string{}),
	}, &t1_)

	Info.Printf("module id = %s\n", t1.Id)
	testLinkModules(t, srv, t1_.Id, "i:"+links[0].Name)
	testLinkModules(t, srv, t1_.Id, "i:"+links[1].Name)

	var wg_ sync.WaitGroup
	wg_.Add(1)
	go hover.RunInNs(nets[0], func() error {
		defer wg_.Done()
		out_, err_ := exec.Command("ping", "-c", "1", "10.10.1.2").Output()
		if err_ != nil {
			t.Error(string(out_), err_)
		}
		return nil
	})
	wg_.Wait()
}

func TestModulePolicy(t *testing.T) {
	srv, cleanup := testSetup(t)
	defer cleanup()

	testns1 := hover.NewNs()
	defer testns1.Close()
	testns2 := hover.NewNs()
	defer testns2.Close()

	l1, err := hover.NewVeth(testns1, "ns1", "eth0", "10.10.1.1/24", nil)
	if err != nil {
		t.Error(err)
	}
	defer netlink.LinkDel(l1)
	l2, err := hover.NewVeth(testns2, "ns2", "eth0", "10.10.1.2/24", nil)
	if err != nil {
		t.Error(err)
	}
	defer netlink.LinkDel(l2)

	var t1, t2 api.Module

	// create a redirect bpf/forward module
	testOne(t, testCase{
		url:  srv.URL + "/modules/",
		body: wrapCode(t, redirectC, []string{}),
	}, &t2)
	Info.Printf("Forward module id=%s\n", t2.Id)

	// create a allow and count bpf/policy module
	testOne(t, testCase{
		url:  srv.URL + "/modules/",
		body: wrapCodePolicy(t, policyC, []string{t2.Id}),
	}, &t1)
	Info.Printf("Policy module id=%s\n", t1.Id)

	// populate entries in the redirect bpf table
	testSetTableEntry(t, srv, t2.Id, "redirect", 1, 2)
	testSetTableEntry(t, srv, t2.Id, "redirect", 2, 1)

	// create ns1 <-> t2 <-> ns2
	testLinkModules(t, srv, "i:"+l1.Name, t2.Id)
	testLinkModules(t, srv, t2.Id, "i:"+l2.Name)

	var wg sync.WaitGroup
	wg.Add(1)
	go hover.RunInNs(testns1, func() error {
		defer wg.Done()
		out, err := exec.Command("ping", "-c", "1", "10.10.1.2").Output()
		if err != nil {
			t.Error(string(out), err)
		}
		return nil
	})
	wg.Wait()

	var c1, c2 api.ModuleTableEntry
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

	// remove policy
	testOne(t, testCase{
		url:    srv.URL + "/modules/" + t1.Id,
		body:   wrapCodePolicy(t, policyC, []string{}),
		method: "PUT",
	}, &t1)
}
