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
struct icmp_t {
  unsigned char type;
  unsigned char code;
  unsigned short checksum;
} BPF_PACKET_HEADER;

BPF_TABLE("hash", u32, u32, endpoints, 1024);

struct match {
  u16 sport;
  u16 dport;
  u8 proto;
  u8 direction;
};
BPF_TABLE("hash", struct match, int, rules, 1024);

static int handle_tx(void *skb, struct metadata *md) {
  u8 *cursor = 0;
  struct match m = {};
  int ret = RX_DROP;
  u32 dst_tag = 0, src_tag = 0;
  if (md->data[0].type == 1)
    src_tag = md->data[0].value;

  ethernet: {
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    u16 ethertype = ethernet->type;
    switch (ethertype) {
    case ETH_P_IP: goto ip;
    case ETH_P_IPV6: goto ip6;
    case ETH_P_ARP: goto arp;
    default: goto DONE;
    }
  }

  ip: {
    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
    u32 dst_ip = ip->dst;
    m.proto = ip->nextp;

    u32 *tag = endpoints.lookup(&dst_ip);
    if (!tag)
      goto DONE;
    dst_tag = *tag;
    switch (m.proto) {
      case 1: goto icmp;
      case 6: goto tcp;
      case 17: goto udp;
      default: goto DONE;
    }
  }

  ip6: {
    goto DONE;
  }

  icmp: {
    struct icmp_t *icmp = cursor_advance(cursor, sizeof(*icmp));
    goto EOP;
  }

  tcp: {
    struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));
    m.dport = tcp->dst_port;
    m.sport = tcp->src_port;
    goto EOP;
  }

  udp: {
    struct udp_t *udp = cursor_advance(cursor, sizeof(*udp));
    m.dport = udp->dport;
    m.sport = udp->sport;
    goto EOP;
  }

  arp: {
    return RX_OK;
  }

EOP: ;
  struct match m1 = {m.sport, m.dport, m.proto, 0};
  int *result = rules.lookup(&m1);
  if (result) {
    ret = *result;
    goto DONE;
  }
  struct match m2 = {m.sport, 0, m.proto, 1};
  result = rules.lookup(&m2);
  if (result) {
    ret = *result;
    goto DONE;
  }
  struct match m3 = {0, m.dport, m.proto, 2};
  result = rules.lookup(&m3);
  if (result) {
    ret = *result;
    goto DONE;
  }

DONE:
  return ret;
}

static int handle_rx(void *skb, struct metadata *md) {
  u8 *cursor = 0;
  u32 src_tag = 0;
  int ret = RX_OK;

  ethernet: {
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    u16 ethertype = ethernet->type;
    switch (ethertype) {
    case ETH_P_IP: goto ip;
    case ETH_P_IPV6: goto ip6;
    case ETH_P_ARP: goto arp;
    default: goto DONE;
    }
  }

  ip: {
    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
    u32 src_ip = ip->src;

    u32 *tag = endpoints.lookup(&src_ip);
    if (!tag)
      goto DONE;
    src_tag = *tag;
    goto DONE;
  }

  ip6: {
    goto DONE;
  }

  arp: {
    goto DONE;
  }

DONE:
  if (src_tag != 0) {
    md->data[0].type = 1;
    md->data[0].value = src_tag;
  }

  return ret;
}
`

var dataplane *Dataplane

func init() {
	dataplane = NewDataplane(":memory:")
}

type moduleEntry struct {
	Id          string                 `json:"id"`
	ModuleType  string                 `json:"module_type"`
	DisplayName string                 `json:"display_name"`
	Perm        string                 `json:"permissions"`
	Config      map[string]interface{} `json:"config"`
}

type tableEntry struct {
	Key   string `json:"key"`
	Value string `json:"value"`
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

func (d *Dataplane) postObject(url string, requestObj interface{}, responseObj interface{}) (err error) {
	b, err := json.Marshal(requestObj)
	if err != nil {
		return
	}
	Debug.Printf(d.baseUrl)
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
			"code":     filterImplC,
			"handlers": []string{"handle_rx", "handle_tx"},
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

func epgToId(epgName string) int {
	// TODO: store in the DB a name->id mapping
	switch epgName {
	case "client":
		return 1
	case "web":
		return 2
	}
	return 0
}

func (d *Dataplane) ParsePolicy(policy *Policy) (err error) {
	Debug.Println("ParsePolicy")
	//consumerId := epgToId(policy.ConsumerEpgId)
	//providerId := epgToId(policy.ProviderEpgId)
	for _, ruleGroupConstrained := range policy.PolicyRuleGroups {
		for _, ruleGroup := range ruleGroupConstrained.PolicyRuleGroups {
			for _, rule := range ruleGroup.ResolvedRules {
				for _, classifier := range rule.Classifiers {
					m := classifier.ToMatch()
					k := fmt.Sprintf("{ %d %d %d %d }", m.SourcePort, m.DestPort, m.Proto, m.Direction)
					v := "2" // drop
					if rule.IsAllow() {
						v = "0"
					}
					obj := &tableEntry{Key: k, Value: v}
					err = d.postObject("/modules/"+d.id+"/tables/rules/entries/", obj, nil)
					if err != nil {
						return
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
	if err != nil {
		return
	}
	//err = d.deleteObject("/modules/"+d.id+"/tables/endpoints/entries/"+ip, nil, nil)
	return
}
