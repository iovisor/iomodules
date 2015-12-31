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
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

var filterImplC string = `
BPF_TABLE("hash", u32, u32, endpoints, 1024);
static int handle_rx(void *pkt, struct metadata *md) {
  return RX_OK;
}
`

var dataplane *Dataplane

func init() {
	dataplane = NewDataplane(":memory:")
}

type Dataplane struct {
	client  *http.Client
	baseUrl string
	id      string
	db      *sqlx.DB
}

func NewDataplane(sqlUrl string) *Dataplane {
	client := &http.Client{}
	d := &Dataplane{
		client: client,
		db:     sqlx.MustConnect("sqlite3", sqlUrl),
	}
	d.db.Exec(`
CREATE TABLE endpoints (
	ip CHAR(50)     PRIMARY KEY NOT NULL,
	tenant CHAR(40) NOT NULL,
	epg CHAR(40)    NOT NULL
);
`)
	return d
}

type moduleEntry struct {
	Id          string                 `json:"id"`
	ModuleType  string                 `json:"module_type"`
	DisplayName string                 `json:"display_name"`
	Perm        string                 `json:"permissions"`
	Config      map[string]interface{} `json:"config"`
}

func (d *Dataplane) postObject(url string, requestObj interface{}, responseObj interface{}) (err error) {
	b, err := json.Marshal(requestObj)
	if err != nil {
		return
	}
	resp, err := d.client.Post(d.baseUrl+url, "application/json", bytes.NewReader(b))
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var body []byte
		if body, err = ioutil.ReadAll(resp.Body); err != nil {
			Error.Print(string(body))
		}
		return fmt.Errorf("module server returned %s", resp.Status)
	}
	if responseObj != nil {
		err = json.NewDecoder(resp.Body).Decode(responseObj)
	}
	return
}

func (d *Dataplane) Init(baseUrl string) error {
	d.baseUrl = baseUrl
	req := map[string]interface{}{
		"module_type":  "bpf",
		"display_name": "gbp",
		"config": map[string]interface{}{
			"code": filterImplC,
		},
	}
	var module moduleEntry
	err := d.postObject("/modules/", req, &module)
	if err != nil {
		return err
	}
	d.id = module.Id
	return nil
}

func (d *Dataplane) Id() string {
	return d.id
}

func (d *Dataplane) Close() error {
	return nil
}

func (d *Dataplane) ParsePolicy(policy *Policy) (err error) {
	Debug.Println("ParsePolicy")
	for _, ruleGroupConstrained := range policy.PolicyRuleGroups {
		for _, ruleGroup := range ruleGroupConstrained.PolicyRuleGroups {
			for _, rule := range ruleGroup.ResolvedRules {
				for _, action := range rule.Actions {
					Debug.Printf("%s/%s/%s\n", ruleGroup.ContractId, rule.Name, action.Name)
				}
				for _, classifier := range rule.Classifiers {
					for _, param := range classifier.ParameterValues {
						Debug.Printf("%s/%s/%s/%s=%d\n", ruleGroup.ContractId, rule.Name, classifier.Name, param.Name, int(param.Value))
					}
				}
			}
		}
	}
	return
}

type EndpointEntry struct {
	Ip     string `db:"ip"`
	Tenant string `db:"tenant"`
	Epg    string `db:"epg"`
}

func (d *Dataplane) Endpoints() <-chan *EndpointEntry {
	ch := make(chan *EndpointEntry)
	rows, err := d.db.Queryx(`SELECT * FROM endpoints`)
	if err != nil {
		return nil
	}
	go func() {
		defer close(ch)
		for rows.Next() {
			var e EndpointEntry
			err = rows.StructScan(&e)
			if err != nil {
				return
			}
			ch <- &e
		}
	}()
	return ch
}

type tableEntry struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func ipStrToKey(ipStr string) (string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", fmt.Errorf("ipStrToKey: ipStr is not a valid IP address")
	}
	if ip.To4() != nil {
		return fmt.Sprintf("%d", binary.BigEndian.Uint32(ip.To4())), nil
	}
	return "", fmt.Errorf("ipStrToKey: IPv6 support not implemented")
}
func (d *Dataplane) AddEndpoint(ipStr, tenant, epg string) (err error) {
	ipKey, err := ipStrToKey(ipStr)
	if err != nil {
		return
	}

	tx, err := d.db.Begin()
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			Info.Printf("AddEndpoint: rolling back %s\n", ipStr)
			tx.Rollback()
		} else {
			err = tx.Commit()
		}
	}()
	_, err = tx.Exec(`INSERT INTO endpoints (ip, tenant, epg) VALUES (?, ?, ?)`, ipStr, tenant, epg)
	if err != nil {
		return
	}
	obj := &tableEntry{
		Key:   ipKey,
		Value: "1",
	}
	err = d.postObject("/modules/"+d.id+"/tables/endpoints/entries/", obj, nil)
	if err != nil {
		return
	}
	return
}

func (d *Dataplane) DeleteEndpoint(ip string) (err error) {
	tx, err := d.db.Begin()
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		} else {
			err = tx.Commit()
		}
	}()
	_, err = tx.Exec(`DELETE FROM endpoints WHERE ip=?`, ip)
	return
}
