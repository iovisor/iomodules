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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"runtime/debug"
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

type testCase struct {
	url    string    // url of the request
	method string    // which htttp method to use
	body   io.Reader // body of the request
	code   int       // expected pass criteria
}

// wrapCode creates a reader object to encapsulate a program in json
func wrapCode(body string, tags []string) io.Reader {
	return newCodeReader(body, "bpf/forward", "test", tags)
}

// wrapCode creates a reader object to encapsulate a program in json
func wrapCodePolicy(body string, tags []string) io.Reader {
	return newCodeReader(body, "bpf/policy", "policy", tags)
}

func newCodeReader(body string, modtype string, name string, tags []string) io.Reader {
	req := &createModuleRequest{
		ModuleType:  modtype,
		DisplayName: name,
		Tags:        tags,
		Config: map[string]interface{}{
			"code": body,
		},
	}
	b, err := json.Marshal(req)
	if err != nil {
		panic(err)
	}
	return bytes.NewReader(b)
}

func wrapObject(body interface{}) io.Reader {
	b, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	return bytes.NewReader(b)
}

func testSetup(t *testing.T) (*httptest.Server, func()) {
	//os.Remove("/tmp/hover.db")
	s := NewServer()
	if s == nil {
		t.Fatal("Could not start Hover server")
	}
	srv := httptest.NewServer(s.Handler())
	return srv, func() {
		s.Close()
		srv.Close()
	}
}

func testLinkModules(t *testing.T, srv *httptest.Server, from, to string) {
	testOne(t, testCase{
		url: srv.URL + "/links/",
		body: wrapObject(map[string]interface{}{
			"from": from,
			"to":   to,
		}),
	}, nil)
}

func TestModuleCreate(t *testing.T) {
	srv, cleanup := testSetup(t)
	defer cleanup()

	testValues := []testCase{
		{
			url:  srv.URL + "/modules/",
			body: wrapCode(trivialC, []string{}),
		},
		{
			url:  srv.URL + "/modules/",
			body: wrapCode(errorC, []string{}),
			code: http.StatusBadRequest,
		},
		{
			url:  srv.URL + "/modules/",
			body: wrapCode(syntaxErrorC, []string{}),
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
		body: wrapCode(trivialC, []string{}),
	}, &t1)
	testOne(t, testCase{
		url:  srv.URL + "/modules/",
		body: wrapCode(trivialC, []string{}),
	}, &t2)
	testLinkModules(t, srv, "m/"+t1.Id, "m/"+t2.Id)
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
	testOne(t, testCase{
		url:  srv.URL + "/modules/",
		body: wrapCode(redirectC, []string{}),
	}, &t1)

	testOne(t, testCase{
		url:  srv.URL + "/modules/",
		body: wrapCode(redirectC, []string{}),
	}, &t2)

	testLinkModules(t, srv, "m/"+t1.Id, "i/"+l1.Name)
	testLinkModules(t, srv, "m/"+t1.Id, "m/"+t2.Id)
	testLinkModules(t, srv, "i/"+l2.Name, "m/"+t2.Id)

	testSetTableEntry(t, srv, t1.Id, "redirect", 1, 2)
	testSetTableEntry(t, srv, t1.Id, "redirect", 2, 1)
	testSetTableEntry(t, srv, t2.Id, "redirect", 1, 2)
	testSetTableEntry(t, srv, t2.Id, "redirect", 2, 1)
	var wg sync.WaitGroup
	go RunInNs(testns1, func() error {
		defer wg.Done()
		out, err := exec.Command("ping", "-c", "1", "10.10.1.2").Output()
		if err != nil {
			t.Error(string(out), err)
		}
		return nil
	})
	wg.Add(1)
	wg.Wait()
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

	testOne(t, testCase{
		url:  srv.URL + "/modules/",
		body: wrapCode(redirectC, []string{}),
	}, &t2)
	Info.Printf("Forward module id=%s\n", t2.Id[:8])

	testOne(t, testCase{
		url:  srv.URL + "/modules/",
		body: wrapCodePolicy(policyC, []string{"m/" + t2.Id[:8]}),
	}, &t1)
	Info.Printf("Policy module id=%s\n", t1.Id[:8])

	testSetTableEntry(t, srv, t2.Id, "redirect", 1, 2)
	testSetTableEntry(t, srv, t2.Id, "redirect", 2, 1)

	testLinkModules(t, srv, "i/"+l1.Name, "m/"+t2.Id)
	testLinkModules(t, srv, "m/"+t2.Id, "i/"+l2.Name)

	var wg sync.WaitGroup
	go RunInNs(testns1, func() error {
		defer wg.Done()
		out, err := exec.Command("ping", "-c", "1", "10.10.1.2").Output()
		if err != nil {
			t.Error(string(out), err)
		}
		return nil
	})
	wg.Add(1)
	wg.Wait()

	var c1, c2 AdapterTablePair
	testOne(t, testCase{
		url:    srv.URL + "/modules/" + t1.Id + "/tables/counters/entries/0x0",
		body:   nil,
		method: "GET",
	}, &c1)
	if c1.Key != "0x0" || c1.Value == "0x0" {
		t.Fatalf("Expected counter 1 != 0, got %s", c1.Value)
	}
	testOne(t, testCase{
		url:    srv.URL + "/modules/" + t1.Id + "/tables/counters/entries/0x1",
		body:   nil,
		method: "GET",
	}, &c2)
	if c2.Key != "0x1" || c2.Value == "0x0" {
		t.Fatalf("Expected counter 1 != 0, got %s", c2.Value)
	}

	// remove policy
	testOne(t, testCase{
		url:    srv.URL + "/modules/" + t1.Id,
		body:   wrapCodePolicy(policyC, []string{}),
		method: "PUT",
	}, &t1)
}

func testOne(t *testing.T, test testCase, rsp interface{}) {
	client := &http.Client{}

	var resp *http.Response
	var err error
	switch test.method {
	case "", "POST":
		resp, err = client.Post(test.url, "application/json", test.body)
	case "GET":
		resp, err = client.Get(test.url)
	default:
		req, err := http.NewRequest(test.method, test.url, test.body)
		if err != nil {
			t.Fatal(err)
		}
		resp, err = client.Do(req)
	}
	if err != nil {
		t.Fatal(err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		debug.PrintStack()
		t.Fatal(err)
	}
	if test.code == 0 {
		test.code = http.StatusOK
	}
	if resp.StatusCode != test.code {
		debug.PrintStack()
		t.Fatalf("Expected %d, got %d :: %s", test.code, resp.StatusCode, string(body))
	}
	if rsp != nil {
		if err := json.Unmarshal(body, rsp); err != nil {
			t.Fatal(err)
		}
	}
}
