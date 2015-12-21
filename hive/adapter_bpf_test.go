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
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"runtime"
	"sync"
	"testing"
	_ "time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

var (
	trivialC = `
#include "iomodule.h"
static int handle_rx(void *pkt, struct metadata *md) {
	return RX_OK;
}
	`
	errorC = `
#include "iomodule.h"
static int handle_rx(void *pkt, struct metadata *md) {
	*(volatile int*)0 = 0;
	return RX_OK;
}
`

	redirectC = `
#include "iomodule.h"
BPF_TABLE("array", int, int, redirect, 10);
static int handle_rx(void *pkt, struct metadata *md) {
	if (md->in_ifc == 1)
		pkt_redirect(pkt, md, 2);
	else
		pkt_redirect(pkt, md, 1);
	return RX_REDIRECT;
}
`
)

type testCase struct {
	name string    // name of the test
	url  string    // url of the request
	body io.Reader // body of the request
	code int       // expected pass criteria
}

func wrapCode(body string) io.Reader {
	req := &createModuleRequest{
		ModuleType:  "bpf",
		DisplayName: "test",
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

func TestModuleCreate(t *testing.T) {
	srv := httptest.NewServer(NewServer())
	defer srv.Close()

	testValues := []testCase{
		{
			name: "trivial",
			url:  srv.URL + "/modules/",
			body: wrapCode(trivialC),
			code: http.StatusOK,
		},
		{
			name: "error",
			url:  srv.URL + "/modules/",
			body: wrapCode(errorC),
			code: http.StatusBadRequest,
		},
	}
	for _, test := range testValues {
		testOne(t, test)
	}
}

func TestModuleConnect(t *testing.T) {
	srv := httptest.NewServer(NewServer())
	defer srv.Close()

	var t1 moduleEntry
	var t2 moduleEntry
	rsp1 := testOne(t, testCase{
		name: "trivial1",
		url:  srv.URL + "/modules/",
		body: wrapCode(trivialC),
		code: http.StatusOK,
	})
	if err := json.Unmarshal(rsp1, &t1); err != nil {
		t.Error(err)
	}
	rsp2 := testOne(t, testCase{
		name: "trivial2",
		url:  srv.URL + "/modules/",
		body: wrapCode(trivialC),
		code: http.StatusOK,
	})
	if err := json.Unmarshal(rsp2, &t2); err != nil {
		t.Error(err)
	}
	testOne(t, testCase{
		name: "connect",
		url:  srv.URL + "/links/",
		body: wrapObject(map[string]interface{}{
			"modules":    []string{t1.Id, t2.Id},
			"interfaces": []string{"", ""},
		}),
		code: http.StatusOK,
	})
}

func nsContext() func() {
	runtime.LockOSThread()
	return func() {
		netns.Set(initNs)
		runtime.UnlockOSThread()
	}
}

var (
	initNs netns.NsHandle
)

func init() {
	initNs, _ = netns.Get()
}

func runInNs(fd netns.NsHandle, fn func() error) error {
	defer nsContext()()
	if err := netns.Set(fd); err != nil {
		return err
	}
	if err := fn(); err != nil {
		return err
	}
	return nil
}

func newVeth(name, dstName, ip string, n netns.NsHandle) (link *netlink.Veth, err error) {
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
	err = runInNs(n, func() error {
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

func newNs() netns.NsHandle {
	runtime.LockOSThread()
	origns, err := netns.Get()
	if err != nil {
		panic(err)
	}
	newNs, err := netns.New()
	if err != nil {
		panic(err)
	}
	if err := netns.Set(origns); err != nil {
		panic(err)
	}
	runtime.UnlockOSThread()
	return newNs
}

func TestModuleRedirect(t *testing.T) {
	srv := httptest.NewServer(NewServer())
	defer srv.Close()

	testns1 := newNs()
	defer testns1.Close()
	testns2 := newNs()
	defer testns2.Close()

	l1, err := newVeth("ns1", "eth0", "10.10.1.1/24", testns1)
	if err != nil {
		t.Error(err)
	}
	defer netlink.LinkDel(l1)
	l2, err := newVeth("ns2", "eth0", "10.10.1.2/24", testns2)
	if err != nil {
		t.Error(err)
	}
	defer netlink.LinkDel(l2)

	var t1 moduleEntry
	rsp1 := testOne(t, testCase{
		name: "redirect",
		url:  srv.URL + "/modules/",
		body: wrapCode(redirectC),
		code: http.StatusOK,
	})
	if err := json.Unmarshal(rsp1, &t1); err != nil {
		t.Error(err)
	}

	testOne(t, testCase{
		name: "connect",
		url:  srv.URL + "/links/",
		body: wrapObject(map[string]interface{}{
			"modules":    []string{t1.Id, "host"},
			"interfaces": []string{"", l1.Name},
		}),
		code: http.StatusOK,
	})

	testOne(t, testCase{
		name: "connect",
		url:  srv.URL + "/links/",
		body: wrapObject(map[string]interface{}{
			"modules":    []string{t1.Id, "host"},
			"interfaces": []string{"", l2.Name},
		}),
		code: http.StatusOK,
	})
	var wg sync.WaitGroup
	go func() {
		runInNs(testns1, func() error {
			_, err := exec.Command("ping", "-c", "1", "10.10.1.2").Output()
			if err != nil {
				t.Error(err)
			}
			return nil
		})
		wg.Done()
	}()
	wg.Add(1)
	wg.Wait()
	//time.Sleep(10 * time.Second)
}

func testOne(t *testing.T, test testCase) []byte {
	client := &http.Client{}

	resp, err := client.Post(test.url, "application/json", test.body)
	if err != nil {
		panic(err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Error(err)
	}
	if resp.StatusCode != test.code {
		t.Errorf("Expected %d, got %d", test.code, resp.StatusCode)
	}
	return body
}
