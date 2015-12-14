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
	"testing"
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
