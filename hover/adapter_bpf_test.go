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
	req := &createModuleRequest{
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

	var t1, t2 moduleEntry
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
	links, nets, cleanup2 := testNetnsPair(t)
	defer cleanup2()

	var t1, t2 moduleEntry
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
	go RunInNs(nets[0], func() error {
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

type policyEntry struct {
	Id     string `json:"id"`
	Module string `json:"module"`
}

func TestModulePolicy(t *testing.T) {
	srv, cleanup := testSetup(t)
	defer cleanup()

	testns1 := NewNs()
	defer testns1.Close()
	testns2 := NewNs()
	defer testns2.Close()

	l1, err := NewVeth(testns1, "ns1", "eth0", "10.10.1.1/24", nil)
	if err != nil {
		t.Error(err)
	}
	defer netlink.LinkDel(l1)
	l2, err := NewVeth(testns2, "ns2", "eth0", "10.10.1.2/24", nil)
	if err != nil {
		t.Error(err)
	}
	defer netlink.LinkDel(l2)

	var t1, t2 moduleEntry

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
	go RunInNs(testns1, func() error {
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

	// remove policy
	testOne(t, testCase{
		url:    srv.URL + "/modules/" + t1.Id,
		body:   wrapCodePolicy(t, policyC, []string{}),
		method: "PUT",
	}, &t1)
}
