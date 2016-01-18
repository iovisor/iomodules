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

var iomoduleH string = `
#include <bcc/proto.h>
#include <uapi/linux/pkt_cls.h>

enum {
	RX_OK,
	RX_REDIRECT,
	RX_DROP,
	RX_RECIRCULATE,
	RX_ERROR,
};

struct type_value {
	u64 type:8;
	u64 value:56;
};
struct metadata {
	// An array of type/value pairs for the module to do with as it pleases. The
	// array is initialized to zero when the event first enters the module chain.
	// The values are preserved across modules.
	struct type_value data[8];

	// A field reserved for use by the wrapper and helper functions.
	u32 is_egress:1;
	u32 flags:31;

	// The length of the packet currently being processed. Read-only.
	u32 pktlen;

	// The module id currently processing the packet.
	int module_id;

	// The interface on which a packet was received. Numbering is local to the
	// module.
	int in_ifc;

	// If the module intends to forward the packet, it must call pkt_redirect to
	// set this field to determine the next-hop.
	int redir_ifc;

	int clone_ifc;
};

// iomodule must implement this function to attach to the networking stack
static int handle_rx(void *pkt, struct metadata *md);
static int handle_tx(void *pkt, struct metadata *md);

static int pkt_redirect(void *pkt, struct metadata *md, int ifc);
static int pkt_mirror(void *pkt, struct metadata *md, int ifc);
static int pkt_drop(void *pkt, struct metadata *md);
`

var patchC string = `
#include <linux/ptrace.h>

BPF_TABLE_PUBLIC("array", int, struct metadata, metadata, 8);

BPF_TABLE("prog", int, int, modules, 1024);

struct link_key {
	int module_id;
	int ifc;
	unsigned char is_egress;
	char pad[3];
};

struct link {
	int module_id;
	int ifc;
	u64 packets;
	u64 bytes;
};

BPF_TABLE("hash", struct link_key, struct link, links, 1024);

// table for tracking metadata in skbs when packet is in-kernel
BPF_TABLE("hash", uintptr_t, struct metadata, skb_metadata, 10240);

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

int recv_netdev_ingress(struct __sk_buff *skb) {
	return recv_netdev(skb, 0);
}

int recv_netdev_egress(struct __sk_buff *skb) {
	return recv_netdev(skb, 1);
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
`

var wrapperC string = `
BPF_TABLE("extern", int, struct metadata, metadata, 8);
BPF_TABLE("prog", int, int, modules, 3);

#ifdef RX_WRAPPER
int handle_rx_wrapper(struct __sk_buff *skb) {
	int md_id = skb->cb[0];
	struct metadata *md = metadata.lookup(&md_id);
	if (!md) {
		bpf_trace_printk("rx: metadata lookup failed\n");
		return TC_ACT_SHOT;
	}
	// copy to stack in cases llvm spills map pointers to stack
	//struct metadata local_md = *md;
	//local_md.flags = 0;
	//local_md.redir_ifc = 0;
	//local_md.clone_ifc = 0;
	//md->flags = 0;
	md->clone_ifc = 0;

	int rc = handle_rx(skb, md);

	// TODO: implementation
	switch (rc) {
		case RX_OK:
			break;
		case RX_REDIRECT:
			break;
		case RX_RECIRCULATE:
			modules.call(skb, 1);
			break;
		case RX_DROP:
			return TC_ACT_SHOT;
	}
	//metadata.update(&md_id, &local_md);
	modules.call(skb, 0);
	return TC_ACT_SHOT;
}
#endif

#ifdef TX_WRAPPER
int handle_tx_wrapper(struct __sk_buff *skb) {
	int md_id = skb->cb[0];
	struct metadata *md = metadata.lookup(&md_id);
	if (!md) {
		bpf_trace_printk("tx: metadata lookup failed\n");
		return TC_ACT_SHOT;
	}
	// copy to stack in cases llvm spills map pointers to stack
	//struct metadata local_md = *md;
	//local_md.flags = 0;
	//local_md.redir_ifc = 0;
	//local_md.clone_ifc = 0;
	//md->flags = 0;
	md->clone_ifc = 0;

	int rc = handle_tx(skb, md);

	// TODO: implementation
	switch (rc) {
		case RX_OK:
			break;
		case RX_REDIRECT:
			break;
		case RX_RECIRCULATE:
			modules.call(skb, 2);
			break;
		case RX_DROP:
			return TC_ACT_SHOT;
	}
	//metadata.update(&md_id, &local_md);
	modules.call(skb, 0);
	return TC_ACT_SHOT;
}
#endif

static int pkt_redirect(void *pkt, struct metadata *md, int ifc) {
	md->redir_ifc = ifc;
	return TC_ACT_OK;
}

static int pkt_mirror(void *pkt, struct metadata *md, int ifc) {
	md->clone_ifc = ifc;
	return TC_ACT_OK;
}
`
