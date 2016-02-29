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

package dnsmon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	_ "net"
	"net/http"
)

var filterImplC string = `

struct ip6_t {
	unsigned int        ver:4;
	unsigned int        priority:8;
	unsigned int        flow_label:20;
	unsigned short      payload_len;
	unsigned char       next_header;
	unsigned char       hop_limit;
	unsigned long long  src_hi;
	unsigned long long  src_lo;
	unsigned long long  dst_hi;
	unsigned long long  dst_lo;
} BPF_PACKET_HEADER;

struct ip6_opt_t {
	unsigned char  next_header;
	unsigned char  ext_len;
	unsigned char  pad[6];
} BPF_PACKET_HEADER;

struct icmp6_t {
	unsigned char   type;
	unsigned char   code;
	unsigned short  checksum;
} BPF_PACKET_HEADER;

struct Counter {
	u64 rx_pkts;
	u64 tx_pkts;
	u64 rx_bytes;
	u64 tx_bytes;
};

struct Ip4Key {
	u32 src;
	u32 dst;
};

struct Ip6Key {
	u64 src_hi;
	u64 src_lo;
	u64 dst_hi;
	u64 dst_lo;
};

BPF_TABLE("hash", struct Ip4Key, struct Counter, ip4_flows, 10240);
BPF_TABLE("hash", struct Ip6Key, struct Counter, ip6_flows, 10240);

enum direction {
	DIRECTION_IN,
	DIRECTION_OUT,
};

static u8 pop_ipv6_headers(void *skb, u8 **cursor, u8 next_header) {
	struct ip6_opt_t *opt = (void *)(*cursor);

	switch (next_header) {
		case 0: goto opt0;
		case 60: goto opt60_1;
		case 43: goto opt43;
		case 44: goto opt44;
		//case 51: goto opt51;
		//case 50: goto opt50;
		//case 135: goto opt135;
		default: goto DONE;
	}

	opt0: {
		opt = cursor_advance(*cursor, sizeof(*opt));
		u8 ext_len = opt->ext_len << 3;
		cursor_advance(*cursor, ext_len);
		switch (opt->next_header) {
			case 60: goto opt60_1;
			case 43: goto opt43;
			case 44: goto opt44;
			//case 51: goto opt51;
			//case 50: goto opt50;
			//case 135: goto opt135;
			default: goto DONE;
		}
	}

	opt60_1: {
		opt = cursor_advance(*cursor, sizeof(*opt));
		u8 ext_len = opt->ext_len << 3;
		cursor_advance(*cursor, ext_len);
		switch (opt->next_header) {
			case 43: goto opt43;
			case 44: goto opt44;
			//case 51: goto opt51;
			//case 50: goto opt50;
			//case 135: goto opt135;
			default: goto DONE;
		}
	}


	opt43: {
		opt = cursor_advance(*cursor, sizeof(*opt));
		u8 ext_len = opt->ext_len << 3;
		cursor_advance(*cursor, ext_len);
		switch (opt->next_header) {
			case 44: goto opt44;
			//case 51: goto opt51;
			//case 50: goto opt50;
			case 60: goto opt60_2;
			//case 135: goto opt135;
			default: goto DONE;
		}
	}

	opt44: {
		opt = cursor_advance(*cursor, sizeof(*opt));
		switch (opt->next_header) {
			//case 51: goto opt51;
			//case 50: goto opt50;
			case 60: goto opt60_2;
			//case 135: goto opt135;
			default: goto DONE;
		}
	}

#if 0
	opt51: {
		opt = cursor_advance(*cursor, sizeof(*opt));
		u8 ext_len = opt->ext_len << 2;
		cursor_advance(*cursor, ext_len);
		switch (opt->next_header) {
			case 50: goto opt50;
			//case 135: goto opt135;
			case 60: goto opt60_2;
			default: goto DONE;
		}
	}

	opt50: {
		opt = cursor_advance(*cursor, sizeof(*opt));
		u8 ext_len = opt->ext_len << 2;
		cursor_advance(*cursor, ext_len);
		switch (opt->next_header) {
			//case 135: goto opt135;
			case 60: goto opt60_2;
			default: goto DONE;
		}
	}
#endif

	opt60_2: {
		opt = cursor_advance(*cursor, sizeof(*opt));
		u8 ext_len = opt->ext_len << 3;
		cursor_advance(*cursor, ext_len);
		switch (opt->next_header) {
			//case 135: goto opt135;
			default: goto DONE;
		}
	}

#if 0
	opt135: {
		opt = cursor_advance(*cursor, sizeof(*opt));
		u8 ext_len = opt->ext_len << 3;
		cursor_advance(*cursor, ext_len);
		switch (opt->next_header) {
			case 60: goto opt60_2;
			//case 135: goto opt135;
			default: goto DONE;
		}
	}
#endif

DONE:
	return opt->next_header;
}

static int handle_any(void *skb, struct metadata *md, enum direction direction) {
	u8 *cursor = 0;
	int ret = RX_OK;

	struct Counter *val = NULL;
	struct Ip4Key ip4key = {};
	struct Ip6Key ip6key = {};
	bool v4valid = false;
	bool v6valid = false;

	ethernet: {
		struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
		u16 ethertype = ethernet->type;
		switch (ethertype) {
			case ETH_P_IP: goto ip;
			case ETH_P_IPV6: goto ip6;
			default: goto DONE;
		}
	}

	ip: {
		struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
		if (direction == DIRECTION_OUT) {
			ip4key.src = ip->src;
			ip4key.dst = ip->dst;
		} else {
			ip4key.dst = ip->src;
			ip4key.src = ip->dst;
		}
		v4valid = true;
		u8 hlen_bytes = ip->hlen << 2;
		cursor_advance(cursor, hlen_bytes - sizeof(*ip));
		u8 nextp = ip->nextp;
		switch (nextp) {
			case 6: goto tcp;
			case 17: goto udp;
			default: goto DONE;
		}
	}

	ip6: {
		struct ip6_t *ip6 = cursor_advance(cursor, sizeof(*ip6));
		if (direction == DIRECTION_OUT) {
			ip6key.src_lo = ip6->src_lo;
			ip6key.src_hi = ip6->src_hi;
			ip6key.dst_lo = ip6->dst_lo;
			ip6key.dst_hi = ip6->dst_hi;
		} else {
			ip6key.dst_lo = ip6->src_lo;
			ip6key.dst_hi = ip6->src_hi;
			ip6key.src_lo = ip6->dst_lo;
			ip6key.src_hi = ip6->dst_hi;
		}
		v6valid = true;
		u8 next_header = pop_ipv6_headers(skb, &cursor, ip6->next_header);
		switch (next_header) {
			case 6: goto tcp;
			case 17: goto udp;
			default: goto DONE;
		}
	}

	udp: {
		struct udp_t *udp = cursor_advance(cursor, sizeof(*udp));
		if ((udp->dport == 53 && direction == DIRECTION_IN) ||
				(udp->sport == 53 && direction == DIRECTION_OUT)) {
			goto LOOKUP;
		}
		goto DONE;
	}

	tcp: {
		struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));
		if ((tcp->dst_port == 53 && direction == DIRECTION_IN) ||
				(tcp->src_port == 53 && direction == DIRECTION_OUT)) {
			goto LOOKUP;
		}
		goto DONE;
	}

	LOOKUP: {
		struct Counter zero = {};
		struct Counter *counter = NULL;
		if (v4valid) {
			counter = ip4_flows.lookup_or_init(&ip4key, &zero);
		} else if (v6valid) {
			counter = ip6_flows.lookup_or_init(&ip6key, &zero);
		} else {
			goto DONE;
		}
		if (direction == DIRECTION_OUT) {
			counter->tx_pkts++;
			counter->tx_bytes += md->pktlen;
		} else {
			counter->rx_pkts++;
			counter->rx_bytes += md->pktlen;
		}
	}

DONE:
	return ret;
}

static int handle_rx(void *skb, struct metadata *md) {
	return handle_any(skb, md, DIRECTION_OUT);
}
static int handle_tx(void *skb, struct metadata *md) {
	return handle_any(skb, md, DIRECTION_IN);
}
`

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

type moduleEntry struct {
	Id          string                 `json:"id"`
	ModuleType  string                 `json:"module_type"`
	DisplayName string                 `json:"display_name"`
	Perm        string                 `json:"permissions"`
	Config      map[string]interface{} `json:"config"`
}

func (d *Dataplane) Init(baseUrl string) error {
	d.baseUrl = baseUrl
	req := map[string]interface{}{
		"module_type":  "bpf",
		"display_name": "dnsmon",
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
