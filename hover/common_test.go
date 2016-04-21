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
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"runtime/debug"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

type testCase struct {
	url    string    // url of the request
	method string    // which htttp method to use
	body   io.Reader // body of the request
	code   int       // expected pass criteria
}

func testWrapObject(t *testing.T, body interface{}) io.Reader {
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
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

func testNetnsPair(t *testing.T) ([]*netlink.Veth, []netns.NsHandle, func()) {
	testns1 := NewNs()
	testns2 := NewNs()

	cleanup := func() {
		testns2.Close()
		testns1.Close()
	}

	l1, err := NewVeth(testns1, "ns1", "eth0", "10.10.1.1/24", nil)
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	l2, err := NewVeth(testns2, "ns2", "eth0", "10.10.1.2/24", nil)
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	return []*netlink.Veth{l1, l2}, []netns.NsHandle{testns1, testns2}, cleanup
}

func testLinkModules(t *testing.T, srv *httptest.Server, from, to string) string {
	var l linkEntry
	testOne(t, testCase{
		url: srv.URL + "/links/",
		body: testWrapObject(t, map[string]interface{}{
			"from": from,
			"to":   to,
		}),
	}, &l)
	return l.Id
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
