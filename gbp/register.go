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

// Notify southbound renderer of new interfaces

package gbp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type Notifier struct {
	url      string
	client   *http.Client
	location string
}

func NewNotifier(url, location string) *Notifier {
	return &Notifier{
		url:      url,
		client:   &http.Client{},
		location: location,
	}
}

type l3Address struct {
	IPAddress string `json:"ip-address"`
	L3Context string `json:"l3-context"`
}
type endpoint struct {
	//	Name               string `json:"name"`
	EndpointGroups      []string      `json:"endpoint-groups"`
	NetworkContainment string      `json:"network-containment"`
	L3Address          []l3Address `json:"l3-address"`
	Tenant             string      `json:"tenant"`
	Location           string      `json:"iovisor:uri"`
}
type endpointNotification struct {
	Input *endpoint `json:"input"`
}

func (n *Notifier) NotifyEndpointUp() error {
	Debug.Println("NotifyEndpointUp")
	// hardcoded for now
	l3addr := l3Address{"169.254.0.1", "finance"}
	notification := &endpointNotification{
		Input: &endpoint{
			//			Name:               "client1",
			EndpointGroups:      []string{"bollocks"},
			NetworkContainment: "finance",
			L3Address:          []l3Address{l3addr},
			Tenant:             "pepsi",
			Location:           n.location,
		},
	}
	b, err := json.Marshal(notification)
	if err != nil {
		return err
	}
	r := bytes.NewReader(b)
	req, err := http.NewRequest("POST", n.url+"/restconf/operations/endpoint:register-endpoint", r)
	req.SetBasicAuth("admin", "admin")
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	_, err = ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Bad status %d from upstream", resp.StatusCode)
	}
	return nil
}
func (n *Notifier) NotifyEndpointDown() {
}
