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

package hive

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
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
BPF_TABLE("array", int, u64, counters, 10);
static void incr(int counter) {
	u64 *val = counters.lookup(&counter);
	if (val)
		++(*val);
}
static int handle_rx(void *pkt, struct metadata *md) {
	incr(0);
	return RX_OK;
}
static int handle_tx(void *pkt, struct metadata *md) {
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

func wrapCode(body string, handlers []string) io.Reader {
	req := &createModuleRequest{
		ModuleType:  "bpf",
		DisplayName: "test",
		Config: map[string]interface{}{
			"code":     body,
			"handlers": handlers,
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

func TestModuleCreate(t *testing.T) {
	srv := httptest.NewServer(NewServer())
	defer srv.Close()

	testValues := []testCase{
		{
			url:  srv.URL + "/modules/",
			body: wrapCode(trivialC, []string{"handle_rx"}),
			code: http.StatusOK,
		},
		{
			url:  srv.URL + "/modules/",
			body: wrapCode(errorC, []string{"handle_rx"}),
			code: http.StatusBadRequest,
		},
	}
	for _, test := range testValues {
		testOne(t, test, nil)
	}
}

func TestModuleConnect(t *testing.T) {
	srv := httptest.NewServer(NewServer())
	defer srv.Close()

	var t1, t2 moduleEntry
	testOne(t, testCase{
		url:  srv.URL + "/modules/",
		body: wrapCode(trivialC, []string{"handle_rx"}),
		code: http.StatusOK,
	}, &t1)
	testOne(t, testCase{
		url:  srv.URL + "/modules/",
		body: wrapCode(trivialC, []string{"handle_rx"}),
		code: http.StatusOK,
	}, &t2)
	testOne(t, testCase{
		url: srv.URL + "/links/",
		body: wrapObject(map[string]interface{}{
			"modules":    []string{t1.Id, t2.Id},
			"interfaces": []string{"", ""},
		}),
		code: http.StatusOK,
	}, nil)
}

func TestModuleRedirect(t *testing.T) {
	srv := httptest.NewServer(NewServer())
	defer srv.Close()

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

	var t1 moduleEntry
	testOne(t, testCase{
		url:  srv.URL + "/modules/",
		body: wrapCode(redirectC, []string{"handle_rx"}),
		code: http.StatusOK,
	}, &t1)

	testOne(t, testCase{
		url: srv.URL + "/links/",
		body: wrapObject(map[string]interface{}{
			"modules":    []string{t1.Id, "host"},
			"interfaces": []string{"", l1.Name},
		}),
		code: http.StatusOK,
	}, nil)

	testOne(t, testCase{
		url: srv.URL + "/links/",
		body: wrapObject(map[string]interface{}{
			"modules":    []string{t1.Id, "host"},
			"interfaces": []string{"", l2.Name},
		}),
		code: http.StatusOK,
	}, nil)

	testOne(t, testCase{
		url:  srv.URL + fmt.Sprintf("/modules/%s/tables/redirect/entries/", t1.Id),
		body: strings.NewReader(`{ "key": "1", "value": "2" }`),
		code: http.StatusOK,
	}, nil)

	testOne(t, testCase{
		url:  srv.URL + fmt.Sprintf("/modules/%s/tables/redirect/entries/", t1.Id),
		body: strings.NewReader(`{ "key": "2", "value": "1" }`),
		code: http.StatusOK,
	}, nil)
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

func TestModulePolicy(t *testing.T) {
	srv := httptest.NewServer(NewServer())
	defer srv.Close()

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

	testOne(t, testCase{
		url: srv.URL + "/links/",
		body: wrapObject(map[string]interface{}{
			"modules":    []string{"host", "host"},
			"interfaces": []string{l1.Name, l2.Name},
		}),
		code: http.StatusOK,
	}, nil)

	var t1 moduleEntry
	testOne(t, testCase{
		url:  srv.URL + "/modules/",
		body: wrapCode(policyC, []string{"handle_rx", "handle_tx"}),
		code: http.StatusOK,
	}, &t1)
	testOne(t, testCase{
		url: srv.URL + "/modules/host/interfaces/" + l1.Name + "/policies/",
		body: wrapObject(map[string]interface{}{
			"module": t1.Id,
		}),
		code: http.StatusOK,
	}, nil)

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
		code:   http.StatusOK,
	}, &c1)
	if c1.Key.(string) != "0x0" || c1.Value.(string) == "0x0" {
		t.Fatalf("Expected counter 1 != 0, got %s", c1.Value)
	}
	testOne(t, testCase{
		url:    srv.URL + "/modules/" + t1.Id + "/tables/counters/entries/0x1",
		body:   nil,
		method: "GET",
		code:   http.StatusOK,
	}, &c2)
	if c2.Key.(string) != "0x1" || c2.Value.(string) == "0x0" {
		t.Fatalf("Expected counter 1 != 0, got %s", c2.Value)
	}
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
	}
	if err != nil {
		t.Error(err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Error(err)
	}
	if resp.StatusCode != test.code {
		t.Errorf("Expected %d, got %d", test.code, resp.StatusCode)
	}
	if rsp != nil {
		if err := json.Unmarshal(body, rsp); err != nil {
			t.Error(err)
		}
	}
}
