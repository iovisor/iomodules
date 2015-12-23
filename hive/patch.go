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
	"fmt"
	"strconv"
	"sync"
	"syscall"

	"github.com/vishvananda/netlink"
)

/*
#cgo LDFLAGS: -lbcc
#include <bcc/bpf_common.h>
#include <bcc/libbpf.h>
*/
import "C"

var (
	patchCode          string
	patchPanel         *BpfAdapter
	initPatchPanelOnce sync.Once
)

type PatchPanel struct {
	adapter       *BpfAdapter
	tailcallFd    int
	netdevFd      int
	modules       AdapterTable
	links         AdapterTable
	moduleHandles *HandlePool
}

func initPatchPanelVars() {
	patchCode = `
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
  u32 flags;

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

static int pkt_redirect(void *pkt, struct metadata *md, int ifc);
static int pkt_mirror(void *pkt, struct metadata *md, int ifc);
static int pkt_drop(void *pkt, struct metadata *md);

BPF_TABLE("array", int, struct metadata, metadata, 8);
BPF_TABLE_EXPORT(metadata);

BPF_TABLE("prog", int, int, modules, 1024);

struct link_key {
  int module_id;
  int ifc;
};

struct link {
  int module_id;
  int ifc;
  u64 packets;
  u64 bytes;
};

BPF_TABLE("hash", struct link_key, struct link, links, 1024);

// Invoke the next module in the chain.
// When next module is a bpf function and is successfully invoked, this
// function never returns.
static int invoke_module(struct __sk_buff *skb, struct metadata *md, struct link *link) {
  if (link->module_id != 0) {
    md->in_ifc = link->ifc;
    md->module_id = link->module_id;
    modules.call(skb, md->module_id);
  } else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
    bpf_redirect(link->ifc, 0);
    return TC_ACT_REDIRECT;
#else
    bpf_clone_redirect(skb, link->ifc, 0);
    return TC_ACT_SHOT;
#endif
  }
  return TC_ACT_SHOT;
}

int recv_netdev(struct __sk_buff *skb) {
  int md_id = bpf_get_smp_processor_id();
  struct metadata *md = metadata.lookup(&md_id);
  if (!md)
    return TC_ACT_SHOT;

  skb->cb[0] = md_id;

  struct link_key lkey = {
    .module_id = 0,
    .ifc = skb->ifindex,
  };
  struct link *link = links.lookup(&lkey);
  if (!link) {
    bpf_trace_printk("recv_netdev: miss\n");
    return TC_ACT_SHOT;
  }

  *md = (struct metadata){
    .pktlen = skb->len,
  };
  return invoke_module(skb, md, link);
}

int recv_tailcall(struct __sk_buff *skb) {
  int md_id = skb->cb[0];
  struct metadata *md = metadata.lookup(&md_id);
  if (!md)
    return TC_ACT_SHOT;

  struct link_key lkey = {
    .module_id = md->module_id,
    .ifc = md->redir_ifc,
  };
  struct link *link = links.lookup(&lkey);
  if (!link)
    return TC_ACT_SHOT;

  return invoke_module(skb, md, link);
}
`
}

func NewPatchPanel() (pp *PatchPanel, err error) {
	initPatchPanelOnce.Do(initPatchPanelVars)

	var id string
	id, err = NewUUID4()
	if err != nil {
		return
	}

	pp = &PatchPanel{
		tailcallFd:    -1,
		netdevFd:      -1,
		moduleHandles: NewHandlePool(1024),
	}
	defer func() {
		if err != nil {
			pp.Close()
			pp = nil
		}
	}()
	pp.adapter = &BpfAdapter{
		id:     id,
		name:   "patch",
		config: make(map[string]interface{}),
	}
	pp.adapter.bpf = NewBpfModule(patchCode)
	if pp.adapter.bpf == nil {
		err = fmt.Errorf("PatchPanel: unable to load core module")
		return
	}
	pp.modules = pp.adapter.Table("modules")
	if pp.modules == nil {
		err = fmt.Errorf("PatchPanel: Unable to load modules table")
		return
	}
	Debug.Printf("Patch panel modules table loaded: %v\n", pp.modules.Config())
	pp.links = pp.adapter.Table("links")
	if pp.links == nil {
		err = fmt.Errorf("PatchPanel: Unable to load links table")
		return
	}
	Debug.Printf("Patch panel links table loaded: %v\n", pp.links.Config())
	pp.netdevFd, err = pp.adapter.bpf.Load("recv_netdev", C.BPF_PROG_TYPE_SCHED_ACT)
	if err != nil {
		return
	}
	pp.tailcallFd, err = pp.adapter.bpf.Load("recv_tailcall", C.BPF_PROG_TYPE_SCHED_ACT)
	if err != nil {
		return
	}
	return
}

func (p *PatchPanel) AcquireHandle() (uint, error) {
	return p.moduleHandles.Acquire()
}
func (p *PatchPanel) ReleaseHandle(handle uint) {
	p.moduleHandles.Release(handle)
}

func (p *PatchPanel) Close() {
	if p.adapter != nil {
		p.adapter.Close()
	}
}

func (p *PatchPanel) FD() int {
	return p.tailcallFd
}

func (p *PatchPanel) Register(adapter *BpfAdapter, fd int) error {
	Info.Printf("PatchPanel: Registering module \"%s\"\n", adapter.Name())
	// update the module tail call table
	err := p.modules.Set(fmt.Sprintf("%d", adapter.Handle()), strconv.Itoa(fd))
	if err != nil {
		return err
	}
	return nil
}
func (p *PatchPanel) Unregister(adapter *BpfAdapter) {
	Info.Printf("PatchPanel: Unregistering module \"%s\"\n", adapter.Name())
	if p.modules != nil {
		err := p.modules.Delete(fmt.Sprintf("%d", adapter.Handle()))
		if err != nil {
			Warn.Printf("PatchPanel: error deleting module from table: %s\n", err)
		}
	}
}

func (p *PatchPanel) Connect(adapterA, adapterB Adapter, ifcA, ifcB string) (id string, err error) {
	newId, err := NewUUID4()
	if err != nil {
		return
	}

	if1, err := adapterA.AcquireInterface(ifcA)
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			adapterA.ReleaseInterface(if1)
		}
	}()

	if2, err := adapterB.AcquireInterface(ifcB)
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			adapterB.ReleaseInterface(if2)
		}
	}()

	key1 := fmt.Sprintf("{%d %d }", adapterA.Handle(), if1)
	val1 := fmt.Sprintf("{%d %d 0 0}", adapterB.Handle(), if2)
	if err = p.links.Set(key1, val1); err != nil {
		return
	}
	defer func() {
		if err != nil {
			p.links.Delete(key1)
		}
	}()

	key2 := fmt.Sprintf("{%d %d }", adapterB.Handle(), if2)
	val2 := fmt.Sprintf("{%d %d 0 0}", adapterA.Handle(), if1)
	if err = p.links.Set(key2, val2); err != nil {
		return
	}
	defer func() {
		if err != nil {
			p.links.Delete(key2)
		}
	}()

	if adapterA.Type() == "host" {
		if err = setIngressFd(int(if1), p.netdevFd); err != nil {
			return
		}
	}

	if adapterB.Type() == "host" {
		if err = setIngressFd(int(if2), p.netdevFd); err != nil {
			return
		}
	}

	id = newId
	return
}

func setIngressFd(ifc, fd int) error {
	ingress := &netlink.Ingress{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifc,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_INGRESS,
		},
	}
	if err := netlink.QdiscAdd(ingress); err != nil {
		return fmt.Errorf("failed setting ingress qdisc: %v", err)
	}
	u32 := &netlink.U32{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifc,
			Parent:    ingress.QdiscAttrs.Handle,
			Priority:  1,
			Protocol:  syscall.ETH_P_ALL,
		},
		ClassId: netlink.MakeHandle(1, 1),
		BpfFd:   fd,
	}
	if err := netlink.FilterAdd(u32); err != nil {
		return fmt.Errorf("failed adding ingress filter: %v", err)
	}
	return nil
}

func setFqCodelFd(ifc, fd int) error {
	fq := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifc,
			Handle:    netlink.MakeHandle(1, 0),
			Parent:    netlink.HANDLE_ROOT,
		},
		QdiscType: "fq_codel",
	}
	if err := netlink.QdiscAdd(fq); err != nil {
		return fmt.Errorf("failed setting egress qdisc: %v", err)
	}
	u32 := &netlink.U32{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifc,
			Parent:    fq.QdiscAttrs.Handle,
			Protocol:  syscall.ETH_P_ALL,
			//Handle:    10,
			//Priority:  10,
		},
		ClassId: netlink.MakeHandle(1, 2),
		BpfFd:   fd,
	}
	if err := netlink.FilterAdd(u32); err != nil {
		return fmt.Errorf("failed adding egress filter: %v", err)
	}
	return nil
}
