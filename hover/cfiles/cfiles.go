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

package cfiles

import (
	"fmt"
	"math"
)

const (
	MAX_MODULES    uint = 1024
	MAX_INTERFACES uint = 128

	MD_MAP_SIZE    uint32 = 1024 // Number of elements in the map for metadata
)

// Reserved reasons
const (
	PKT_BROADCAST       uint16 = math.MaxUint16 - iota
	RESERVED_REASON_MIN uint16 = math.MaxUint16 - iota
)

var DefaultCflags = []string{
	fmt.Sprintf("-DMAX_INTERFACES=%d", MAX_INTERFACES),
	fmt.Sprintf("-DMAX_MODULES=%d", MAX_MODULES),
	"-DMAX_METADATA=10240",
	fmt.Sprintf("-DMD_MAP_SIZE=%d", MD_MAP_SIZE),
	fmt.Sprintf("-DPKT_BROADCAST=%d", PKT_BROADCAST),
}

var IomoduleH string = `
#include <bcc/proto.h>
#include <uapi/linux/pkt_cls.h>

#define CONTROLLER_MODULE_ID (MAX_MODULES - 1)

enum {
	RX_OK,
	RX_REDIRECT,
	RX_DROP,
	RX_RECIRCULATE,
	RX_CONTROLLER,
	RX_ERROR,
};

struct chain {
	u32 hops[4];
};
static inline u16 chain_ifc(struct chain *c, int id) {
	return c->hops[id] >> 16;
}
static inline u16 chain_module(struct chain *c, int id) {
	return c->hops[id] & 0xffff;
}

struct type_value {
	u64 type:8;
	u64 value:56;
};
struct metadata {
	// An array of type/value pairs for the module to do with as it pleases. The
	// array is initialized to zero when the event first enters the module chain.
	// The values are preserved across modules.
	struct type_value data[4];

	// A field reserved for use by the wrapper and helper functions.
	u32 is_egress:1;
	u32 flags:31;

	// The length of the packet currently being processed. Read-only.
	u32 pktlen;

	// The module id currently processing the packet.
	u16 module_id;

	// The interface on which a packet was received. Numbering is local to the
	// module.
	u16 in_ifc;

	// If the module intends to forward the packet, it must call pkt_redirect to
	// set this field to determine the next-hop.
	u16 redir_ifc;

	u16 clone_ifc;

	// Why the packet is being sent to the controller
	u16 reason;
};

// iomodule must implement this function to attach to the networking stack
static int handle_rx(void *pkt, struct metadata *md);
static int handle_tx(void *pkt, struct metadata *md);

static int pkt_redirect(void *pkt, struct metadata *md, u16 ifc);
static int pkt_mirror(void *pkt, struct metadata *md, u16 ifc);
static int pkt_drop(void *pkt, struct metadata *md);
`

var NetdevRxC string = `
BPF_TABLE("extern", int, int, modules, MAX_MODULES);
int ingress(struct __sk_buff *skb) {
	//bpf_trace_printk("ingress %d %x\n", skb->ifindex, CHAIN_VALUE0);
	skb->cb[0] = CHAIN_VALUE0;
	skb->cb[1] = CHAIN_VALUE1;
	skb->cb[2] = CHAIN_VALUE2;
	skb->cb[3] = CHAIN_VALUE3;
	modules.call(skb, CHAIN_VALUE0 & 0xffff);
	//bpf_trace_printk("ingress drop\n");
	return 2;
}
`

var NetdevTxC string = `
int egress(struct __sk_buff *skb) {
	//bpf_trace_printk("egress %d\n", INTERFACE_ID);
	bpf_redirect(INTERFACE_ID, 0);
	return 7;
}
`

var NetdevEgressC string = `
BPF_TABLE("extern", int, int, modules, MAX_MODULES);
int egress(struct __sk_buff *skb) {
	//bpf_trace_printk("egress %d %x\n", skb->ifindex, CHAIN_VALUE0);
	skb->cb[0] = CHAIN_VALUE0;
	skb->cb[1] = CHAIN_VALUE1;
	skb->cb[2] = CHAIN_VALUE2;
	skb->cb[3] = CHAIN_VALUE3;
	modules.call(skb, CHAIN_VALUE0 & 0xffff);
	//bpf_trace_printk("egress drop\n");
	return 0;
}
`

var PatchC string = `
#include <linux/ptrace.h>

//BPF_TABLE_PUBLIC("array", int, struct metadata, metadata, NUMCPUS);

BPF_TABLE_PUBLIC("prog", int, int, modules, MAX_MODULES);

// table for tracking metadata in skbs when packet is in-kernel
//BPF_TABLE("hash", uintptr_t, struct metadata, skb_metadata, MAX_METADATA);

#if 0
// Attach to kfree_skbmem kprobe to reclaim metadata.
// This is a bit of a hack, but all of the skb fields are written over when
// traversing some parts of the kernel, like nft or netns boundary.
int metadata_kfree_skbmem(struct pt_regs *ctx, struct sk_buff *skb) {
	uintptr_t skbkey = (uintptr_t)skb | 1;
	skb_metadata.delete(&skbkey);
	return 0;
}

// Invoke the next module in the chain.
// When next module is a bpf function and is successfully invoked, this
// function never returns.
static int invoke_module(struct __sk_buff *skb, struct metadata *md, struct link *link) {
	if (link->module_id != 0) {
		int md_id = bpf_get_smp_processor_id();
		skb->cb[0] = md_id;
		md->in_ifc = link->ifc;
		md->module_id = link->module_id;
		metadata.update(&md_id, md);
		modules.call(skb, md->module_id);
	} else {
		uintptr_t skbkey = (uintptr_t)skb | 1;
		skb_metadata.update(&skbkey, md);
		//bpf_trace_printk("set metadata for 0x%lx\n", skbkey);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
		bpf_redirect(link->ifc, 0);
		return TC_ACT_REDIRECT;
#else
		bpf_clone_redirect(skb, link->ifc, 0);
		return TC_ACT_SHOT;
#endif
	}
	bpf_trace_printk("drop %d\n", link->ifc);
	return TC_ACT_SHOT;
}

static int recv_netdev(struct __sk_buff *skb, bool is_egress) {
	int md_id = bpf_get_smp_processor_id();

	struct metadata md;
	// recover metadata from the skb lookaside table
	// (will not occur for packets that are only rx'd from a netdev once)
	uintptr_t skbkey = (uintptr_t)skb | 1;
	struct metadata *skb_md = skb_metadata.lookup(&skbkey);
	if (skb_md)
		md = *skb_md;
	else
		md = (struct metadata){};

	struct link_key lkey = {
		.module_id = 0,
		.ifc = skb->ifindex,
		.is_egress = is_egress,
	};
	struct link *link = links.lookup(&lkey);
	if (!link) {
		bpf_trace_printk("recv_netdev: miss\n");
		return TC_ACT_SHOT;
	}

	md.pktlen = skb->len;
	md.is_egress = is_egress;
	return invoke_module(skb, &md, link);
}

int recv_tailcall(struct __sk_buff *skb) {
	int md_id = skb->cb[0];
	struct metadata md;
	struct metadata *md_ptr = metadata.lookup(&md_id);
	if (!md_ptr)
		return TC_ACT_SHOT;
	md = *md_ptr;

	struct link_key lkey = {
		.module_id = md.module_id,
	};
	// Either a module should invoke a redirect action, or we need to
	// lookup the next module in the chain.
	if (md.redir_ifc) {
		lkey.ifc = md.redir_ifc;
	} else {
		lkey.ifc = md.in_ifc;
	}
	struct link *link = links.lookup(&lkey);
	if (!link) {
		uintptr_t skbkey = (uintptr_t)skb | 1;
		skb_metadata.update(&skbkey, &md);
		//bpf_trace_printk("set metadata for 0x%lx\n", skbkey);
		//if (md.is_egress)
			return TC_ACT_OK;
		//return TC_ACT_SHOT;
	}
	return invoke_module(skb, &md, link);
}
#endif
`

var WrapperC string = `
//BPF_TABLE("extern", int, struct metadata, metadata, NUMCPUS);
BPF_TABLE("extern", int, int, modules, MAX_MODULES);
BPF_TABLE("array", int, struct chain, forward_chain, MAX_INTERFACES);

static int forward(struct __sk_buff *skb, int out_ifc) {
	struct chain *cur = (struct chain *)skb->cb;
	struct chain *next = forward_chain.lookup(&out_ifc);
	if (next) {
		cur->hops[0] = next->hops[0];
		cur->hops[1] = next->hops[1];
		cur->hops[2] = next->hops[2];
		cur->hops[3] = next->hops[3];
		//bpf_trace_printk("fwd:%d=0x%x %d\n", out_ifc, next->hops[0], chain_module(next, 0));
		modules.call(skb, chain_module(next, 0));
	}
	//bpf_trace_printk("fwd:%d=0\n", out_ifc);
	return TC_ACT_SHOT;
}

static int chain_pop(struct __sk_buff *skb) {
	struct chain *cur = (struct chain *)skb->cb;
	struct chain orig = *cur;
	cur->hops[0] = cur->hops[1];
	cur->hops[1] = cur->hops[2];
	cur->hops[2] = cur->hops[3];
	cur->hops[3] = 0;
	if (cur->hops[0]) {
		modules.call(skb, chain_module(&orig, 1));
	}

	//bpf_trace_printk("pop empty\n");
	return TC_ACT_OK;
}

static int to_controller(struct __sk_buff *skb, u16 reason) {
	skb->cb[1] = reason;
	modules.call(skb, CONTROLLER_MODULE_ID);
	bpf_trace_printk("to controller miss\n");
	return TC_ACT_OK;
}

int handle_rx_wrapper(struct __sk_buff *skb) {
	//bpf_trace_printk("" MODULE_UUID_SHORT ": rx:%d\n", skb->cb[0]);
	struct metadata md = {};
	volatile u32 x = skb->cb[0]; // volatile to avoid a rare verifier error
	md.in_ifc = x >> 16;
	md.module_id = x & 0xffff;
	int rc = handle_rx(skb, &md);

	// TODO: implementation
	switch (rc) {
		case RX_OK:
			return chain_pop(skb);
		case RX_REDIRECT:
			return forward(skb, md.redir_ifc);
		//case RX_RECIRCULATE:
		//	modules.call(skb, 1);
		//	break;
		case RX_DROP:
			return TC_ACT_SHOT;
		case RX_CONTROLLER:
			return to_controller(skb, md.reason);
	}
	return TC_ACT_SHOT;
}

static int pkt_redirect(void *pkt, struct metadata *md, u16 ifc) {
	md->redir_ifc = ifc;
	return TC_ACT_OK;
}

static int pkt_mirror(void *pkt, struct metadata *md, u16 ifc) {
	md->clone_ifc = ifc;
	return TC_ACT_OK;
}

static int pkt_controller(void *pkt, struct metadata *md, u16 reason) {
	md->reason = reason;
	return TC_ACT_OK;
}

static int pkt_set_metadata(struct __sk_buff *skb, u32 md[3]){
	skb->cb[2] = md[0];
	skb->cb[3] = md[1];
	skb->cb[4] = md[2];
	return TC_ACT_OK;
}
`

// Sends the packet to the controller
var ControllerModuleTxC string = `
#include <bcc/proto.h>
#include <bcc/helpers.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>

struct metadata {
	u16 module_id;
	u16 port_id;
	u32 packet_len;
	u16 reason;
	u32 md[3];  // generic metadata
};

BPF_TABLE("array", u32, struct metadata, md_map_tx, MD_MAP_SIZE);
BPF_TABLE("array", u32, u32, index_map_tx, 1);

int controller_module_tx(struct __sk_buff *skb) {
	bpf_trace_printk("to controller\n");

	u32 zero = 0;
	u32 *index = index_map_tx.lookup(&zero);
	if (!index) {
		goto ERROR;
	}

	rcu_read_lock();

	(*index)++;
	*index %= MD_MAP_SIZE;

	u32 i = *index;

	struct metadata *md = md_map_tx.lookup(&i);
	if (!md) {
		rcu_read_unlock();
		goto ERROR;
	}

	volatile u32 x; // volatile to avoid verifier error on kernels < 4.10
	x = skb->cb[0];
	u16 in_ifc = x >> 16;
	u16 module_id = x & 0xffff;

	x = skb->cb[1];
	u16 reason = x & 0xffff;

	md->module_id = module_id;
	md->port_id = in_ifc;
	md->packet_len = skb->len;
	md->reason = reason;

	x=skb->cb[2];
	md->md[0] = x;
	x=skb->cb[3];
	md->md[1] = x;
	x=skb->cb[4];
	md->md[2] = x;

	// bpf_trace_printk("pkt.to.ctrl md(1,2,3) %d %d %d\n",md->md[0],md->md[1],md->md[2]);

	bpf_redirect(CONTROLLER_INTERFACE_ID, 0);

	rcu_read_unlock();
	return 7;
ERROR:
	bpf_trace_printk("Error.......\n");
	return 7;	//TODO: check code
}
`

// Receives packet from controller and forwards it to the IOModule
var ControllerModuleRxC string = `
#include <bcc/proto.h>
#include <bcc/helpers.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>

BPF_TABLE("extern", int, int, modules, MAX_MODULES);

struct metadata {
	u16 module_id;
	u16 port_id;
};

BPF_TABLE("array", u32, struct metadata, md_map_rx, MD_MAP_SIZE);
BPF_TABLE("array", u32, u32, index_map_rx, 1);

int controller_module_rx(struct __sk_buff *skb) {
	bpf_trace_printk("from controller\n");

	u32 zero = 0;
	u32 *index = index_map_rx.lookup(&zero);
	if (!index) {
		goto ERROR;
	}

	rcu_read_lock();

	(*index)++;
	*index %= MD_MAP_SIZE;
	rcu_read_unlock();

	u32 i = *index;

	struct metadata *md = md_map_rx.lookup(&i);
	if (!md) {
		goto ERROR;
	}

	u16 in_ifc = md->port_id;
	u16 module_id = md->module_id;

	skb->cb[0] = in_ifc << 16 | module_id;
	skb->cb[1] = 0;
	skb->cb[2] = 0;
	skb->cb[3] = 0;
	modules.call(skb, module_id);
	return 2;

ERROR:
	bpf_trace_printk("ControllerModuleRX: Error.......\n");
	return 2;
}
`
