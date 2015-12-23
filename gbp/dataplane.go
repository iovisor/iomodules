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

package gbp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
)

var filterImplC string = `
static int handle_rx(void *pkt, struct metadata *md) {
  return RX_OK;
}
`

var dataplane *Dataplane

func init() {
	dataplane = NewDataplane()
}

type Dataplane struct {
	mtx    sync.RWMutex
	client *http.Client
	url    string
	id     string
}

func NewDataplane() *Dataplane {
	client := &http.Client{}
	return &Dataplane{client: client}
}

type moduleEntry struct {
	Id          string                 `json:"id"`
	ModuleType  string                 `json:"module_type"`
	DisplayName string                 `json:"display_name"`
	Perm        string                 `json:"permissions"`
	Config      map[string]interface{} `json:"config"`
}

func (dp *Dataplane) Init(url string) error {
	dp.url = url
	b, err := json.Marshal(map[string]interface{}{
		"module_type":  "bpf",
		"display_name": "gbp",
		"config": map[string]interface{}{
			"code": filterImplC,
		},
	})
	if err != nil {
		return err
	}
	resp, err := dp.client.Post(dp.url+"/modules/", "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if body, err := ioutil.ReadAll(resp.Body); err != nil {
			Error.Print(string(body))
		}
		return fmt.Errorf("module server returned %s", resp.Status)
	}

	var entry moduleEntry
	if err := json.NewDecoder(resp.Body).Decode(&entry); err != nil {
		return err
	}
	Debug.Printf("gbp id %s\n", entry.Id)
	dp.id = entry.Id
	return nil
}

func (dp *Dataplane) Id() string {
	return dp.id
}

func (dp *Dataplane) Close() error {
	return nil
}

func (dp *Dataplane) ParsePolicy(policy *Policy) error {
	Debug.Println("ParsePolicy")
	return nil
}
