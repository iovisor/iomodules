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

package server

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"

	"github.com/iomodules/policy/log"
	"github.com/iomodules/policy/models"
)

var filterImplC string = `

#include <uapi/linux/if_ether.h>

BPF_TABLE("hash", u32, u32, endpoints, 1024);

struct match {
	u32 src_tag;
	u32 dst_tag;
	u16 sport;
	u16 dport;
	u8 proto;
	u8 pad[3];
};

BPF_TABLE("hash", struct match, int, rules, 1024);

static int handle_egress(void *skb, struct metadata *md) {
	u8 *cursor = 0;
	struct match m = {};
	int ret = RX_DROP;
	u32 dst_tag = 0, src_tag = 0;

	//bpf_trace_printk("handle_egress\n");

	ethernet: {
		struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
		u16 ethertype = ethernet->type;
		src_tag = ethernet->src & 0xff;
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
		bpf_trace_printk("dip 0x%x STAG %d DTAG %d\n", ip->dst, src_tag, dst_tag);
		goto EOP;
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
		//bpf_trace_printk("ARP\n");
		return RX_OK;
	}

EOP: ;
	int *result;
	struct match m1 = {src_tag, dst_tag, 0, 0, m.proto};
	result = rules.lookup(&m1);
	if (result) {
		ret = *result;
		bpf_trace_printk("m %d %d = %d\n", src_tag, dst_tag, ret);
		goto DONE;
	}
	struct match m2 = {dst_tag, src_tag, 0, 0, m.proto};
	result = rules.lookup(&m2);
	if (result) {
		ret = *result;
		bpf_trace_printk("m %d %d = %d\n", dst_tag, src_tag, ret);
		goto DONE;
	}

DONE:
	return ret;
}

static int handle_ingress(void *skb, struct metadata *md) {
	u8 *cursor = 0;
	u32 src_tag = 0;
	int ret = RX_OK;
	u64 mac = 0;
	struct ethernet_t *ethernet;

        //bpf_trace_printk("handle_ingress\n");

	ethernet: {
		ethernet = cursor_advance(cursor, sizeof(*ethernet));
		u16 ethertype = ethernet->type;
		switch (ethertype) {
			case ETH_P_IP: goto ip;
			case ETH_P_IPV6: goto ip6;
			case ETH_P_ARP: goto arp;
			default: return RX_OK;
		}
	}

	ip: {
		struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
		u32 src_ip = ip->src;

		u32 *tag = endpoints.lookup(&src_ip);
		if (!tag) {
		   //bpf_trace_printk("sip 0x%x dip 0x%x STAG %d\n", src_ip, ip->dst, 0);
                   return RX_OK;
		}
		src_tag = *tag;
		//bpf_trace_printk("sip 0x%x dip 0x%x STAG %d\n", src_ip, ip->dst, src_tag);
		goto DONE;
	}

	ip6: {
		return RX_OK;
	}

	arp: {
		return RX_OK;
	}

DONE:
	mac = ethernet->src;
	mac = (mac & 0xffffffffff00ULL) | (src_tag & 0x00ff);
	ethernet->src = mac;
	//bpf_trace_printk("DONE : tag: %d, %d, %llx\n", src_tag, ret, mac);
	return ret;
}

static int handle_rx(void *skb, struct metadata *md) {
	if (md->in_ifc == 2)
		return handle_egress(skb, md);
	else if (md->in_ifc == 1)
		return handle_ingress(skb, md);
	return RX_OK;
}
`

//go:generate counterfeiter -o ../fakes/dataplane.go --fake-name Dataplane . dataplane
type dataplane interface {
	AddEndpoint(ip string, epg string, wireid string) error
	DeleteEndpoint(ip string) error
	AddPolicy(sepgId, sourcePort, depgId, destPort, protocol, action string) (err error)
	DeletePolicy(sepgId, sourcePort, depgId, destPort, protocol string) error
	Init(Url string) error
	Id() string
}

type Dataplane struct {
	client  *http.Client
	baseUrl string
	id      string
}

func NewDataplane() *Dataplane {
	client := &http.Client{}
	d := &Dataplane{
		client: client,
	}
	return d
}

func (d *Dataplane) PostObject(url string, requestObj interface{}, responseObj interface{}) error {
	b, err := json.Marshal(requestObj)
	if err != nil {
		return fmt.Errorf("module server returned: %s", err)
	}
	resp, err := d.client.Post(d.baseUrl+url, "application/json", bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("module server returned: %s", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var body []byte
		if body, err = ioutil.ReadAll(resp.Body); err != nil {
			log.Error.Print(string(body))
		}
		return fmt.Errorf("module server returned: %s", resp.Status)
	}
	if responseObj != nil {
		err = json.NewDecoder(resp.Body).Decode(responseObj)
		if err != nil {
			return err
		}
	}
	return nil
}

func (d *Dataplane) putObject(url string, requestObj interface{}, responseObj interface{}) (err error) {
	return nil
}

func (d *Dataplane) deleteObject(url string) error {
	req, err := http.NewRequest("DELETE", d.baseUrl+url, nil)
	if err != nil {
		return fmt.Errorf("module server returned: %s", err)
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("module server returned: %s", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("module server returned: %s", resp.Status)
	}
	return nil
}
func (d *Dataplane) Update() {

}
func (d *Dataplane) Init(baseUrl string) error {
	d.baseUrl = baseUrl
	req := map[string]interface{}{
		"module_type":  "bpf/policy",
		"display_name": "policy",
		"config": map[string]interface{}{
			"code": filterImplC,
		},
		//"tags" : []string {"b:"+modstr, "i:vxlan2050642",},
	}
	var module models.ModuleEntry
	err := d.PostObject("/modules/", req, &module)
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

func (d *Dataplane) AddEndpoint(ip, epg, wireid string) error {
	ipKey, err := ipStrToKey(ip)
	if err != nil {
		return err
	}
	obj := &models.TableEntry{
		Key:   ipKey,
		Value: wireid,
	}
	err = d.PostObject("/modules/"+d.id+"/tables/endpoints/entries/", obj, nil)
	if err != nil {
		return err
	}
	return nil
}

func (d *Dataplane) DeleteEndpoint(ip string) error {
	ipKey, err := ipStrToKey(ip)
	if err != nil {
		return err
	}
	err = d.deleteObject("/modules/" + d.id + "/tables/endpoints/entries/" + ipKey)
	if err != nil {
		return err
	}
	return nil
}

func (d *Dataplane) AddPolicy(sepgId, sourcePort, depgId, destPort, protocol, action string) error {
	var v string
	if len(sourcePort) == 0 {
		sourcePort = "0"
	}
	if len(destPort) == 0 {
		destPort = "0"
	}
	k := fmt.Sprintf("{ %s %s %s %s %s [ 0 0 0 ]}", sepgId, depgId, sourcePort, destPort, protocol)
	if action == "allow" {
		v = "0"
	}
	obj := &models.TableEntry{Key: k, Value: v}
	err := d.PostObject("/modules/"+d.id+"/tables/rules/entries/", obj, nil)
	if err != nil {
		return fmt.Errorf("add policy to dataplane: %s", err)
	}
	return nil
}

func (d *Dataplane) DeletePolicy(sepgId, sourcePort, depgId, destPort, protocol string) error {
	k := fmt.Sprintf("{ %s %s %s %s %s [ 0 0 0 ]}", sepgId, depgId, sourcePort, destPort, protocol)
	err := d.deleteObject("/modules/" + d.id + "/tables/rules/entries/" + k)
	if err != nil {
		return fmt.Errorf("delete policy from dataplane: %s", err)
	}
	return nil
}
