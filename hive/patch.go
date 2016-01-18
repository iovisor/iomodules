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
	"strings"
	"syscall"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/vishvananda/netlink"
)

/*
#cgo LDFLAGS: -lbcc
#include <bcc/bpf_common.h>
#include <bcc/libbpf.h>
*/
import "C"

var (
	patchPanel *BpfAdapter
)

type PatchPanel struct {
	adapter       *BpfAdapter
	tailcallFd    int
	netdevRxFd    int
	netdevTxFd    int
	kfreeFd       int
	modules       AdapterTable
	links         AdapterTable
	moduleHandles *HandlePool
	db            *sqlx.DB
}

func NewPatchPanel() (pp *PatchPanel, err error) {
	var id string
	id, err = NewUUID4()
	if err != nil {
		return
	}

	pp = &PatchPanel{
		tailcallFd:    -1,
		netdevRxFd:    -1,
		netdevTxFd:    -1,
		moduleHandles: NewHandlePool(1024),
		db:            sqlx.MustConnect("sqlite3", ":memory:"),
	}
	pp.db.MustExec(`
CREATE TABLE links (
	id CHAR(36)  PRIMARY KEY NOT NULL,
	src CHAR(36) NOT NULL,
	dst CHAR(36) NOT NULL
);`)
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
	code := strings.Join([]string{iomoduleH, patchC}, "\n")
	pp.adapter.bpf = NewBpfModule(code, []string{})
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
	pp.netdevRxFd, err = pp.adapter.bpf.Load("recv_netdev_ingress", C.BPF_PROG_TYPE_SCHED_ACT)
	if err != nil {
		return
	}
	pp.netdevTxFd, err = pp.adapter.bpf.Load("recv_netdev_egress", C.BPF_PROG_TYPE_SCHED_ACT)
	if err != nil {
		return
	}
	pp.tailcallFd, err = pp.adapter.bpf.Load("recv_tailcall", C.BPF_PROG_TYPE_SCHED_ACT)
	if err != nil {
		return
	}
	pp.kfreeFd, err = pp.adapter.bpf.Load("metadata_kfree_skbmem", C.BPF_PROG_TYPE_KPROBE)
	if err != nil {
		return
	}
	err = pp.adapter.bpf.AttachKprobe("kfree_skbmem", pp.kfreeFd)
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

func (p *PatchPanel) Register(adapter *BpfAdapter, handle uint, fd int) error {
	Info.Printf("PatchPanel: Registering module \"%s\"\n", adapter.Name())
	// update the module tail call table
	err := p.modules.Set(fmt.Sprintf("%d", handle), strconv.Itoa(fd))
	if err != nil {
		Warn.Printf("PatchPanel.Register failed: %s\n", err)
		return err
	}
	return nil
}
func (p *PatchPanel) Unregister(adapter *BpfAdapter) {
	Info.Printf("PatchPanel: Unregistering module \"%s\"\n", adapter.Name())
	if p.modules != nil {
		for i := HandlerRx; i < HandlerMax; i++ {
			h := adapter.Handle(i)
			if h == 0 {
				continue
			}
			err := p.modules.Delete(fmt.Sprintf("%d", h))
			if err != nil {
				Warn.Printf("PatchPanel: error deleting module %s(%d) from table: %s\n", adapter.Name(), h, err)
			}
			p.ReleaseHandle(h)
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

	key1 := fmt.Sprintf("{%d %d 0}", adapterA.Handle(HandlerRx), if1.ID())
	val1 := fmt.Sprintf("{%d %d 0 0}", adapterB.Handle(HandlerRx), if2.ID())
	if err = p.links.Set(key1, val1); err != nil {
		return
	}
	defer func() {
		if err != nil {
			p.links.Delete(key1)
		}
	}()

	key2 := fmt.Sprintf("{%d %d 0}", adapterB.Handle(HandlerRx), if2.ID())
	val2 := fmt.Sprintf("{%d %d 0 0}", adapterA.Handle(HandlerRx), if1.ID())
	if err = p.links.Set(key2, val2); err != nil {
		return
	}
	defer func() {
		if err != nil {
			p.links.Delete(key2)
		}
	}()

	if adapterA.Type() == "host" {
		var link netlink.Link
		if link, err = netlink.LinkByIndex(if1.ID()); err != nil {
			return
		}
		if err = ensureIngressFd(link, p.netdevRxFd); err != nil {
			return
		}
	}

	if adapterB.Type() == "host" {
		var link netlink.Link
		if link, err = netlink.LinkByIndex(if2.ID()); err != nil {
			return
		}
		if err = ensureIngressFd(link, p.netdevRxFd); err != nil {
			return
		}
	}

	id = newId
	return
}

// EnablePolicy adds rcvAdapter as a handler for packets going in and out of srcAdapter.ifcName
func (p *PatchPanel) EnablePolicy(srcAdapter, rcvAdapter Adapter, srcIfc Interface) (id string, err error) {
	newId, err := NewUUID4()
	if err != nil {
		return
	}

	rcvIfc, err := rcvAdapter.AcquireInterface("")
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			rcvAdapter.ReleaseInterface(rcvIfc)
		}
	}()

	cleanupLinkIfError := func(k string) {
		if err != nil {
			p.links.Delete(k)
		}
	}

	k := fmt.Sprintf("{%d %d 0}", srcAdapter.Handle(HandlerRx), srcIfc.ID())
	v := fmt.Sprintf("{%d %d 0 0}", rcvAdapter.Handle(HandlerRx), rcvIfc.ID())
	if o, ok := p.links.Get(k); ok {
		k2 := fmt.Sprintf("{%d %d 0}", rcvAdapter.Handle(HandlerRx), rcvIfc.ID())
		v2 := o.(AdapterTablePair).Value.(string)
		Debug.Printf("existing link %s = %s\n", k, v2)
		if err = p.links.Set(k2, v2); err != nil {
			return
		}
	}
	if err = p.links.Set(k, v); err != nil {
		return
	}
	defer cleanupLinkIfError(k)

	k = fmt.Sprintf("{%d %d 1}", srcAdapter.Handle(HandlerRx), srcIfc.ID())
	v = fmt.Sprintf("{%d %d 0 0}", rcvAdapter.Handle(HandlerTx), rcvIfc.ID())
	Debug.Printf("tx link %s\n", v)
	if o, ok := p.links.Get(k); ok {
		k2 := fmt.Sprintf("{%d %d 1}", rcvAdapter.Handle(HandlerTx), rcvIfc.ID())
		v2 := o.(AdapterTablePair).Value.(string)
		Debug.Printf("existing link %s = %s\n", k, v2)
		if err = p.links.Set(k2, v2); err != nil {
			return
		}
	}
	if err = p.links.Set(k, v); err != nil {
		return
	}
	defer cleanupLinkIfError(k)

	if srcAdapter.Type() == "host" {
		var link netlink.Link
		if link, err = netlink.LinkByIndex(srcIfc.ID()); err != nil {
			return
		}
		if err = ensureIngressFd(link, p.netdevRxFd); err != nil {
			return
		}
		if err = ensureFqCodelFd(link, p.netdevTxFd); err != nil {
			return
		}
	}

	// TODO: insert into a db

	id = newId
	return
}

func ensureIngressFd(link netlink.Link, fd int) error {
	ingress := &netlink.Ingress{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_INGRESS,
		},
	}
	qds, err := netlink.QdiscList(link)
	if err != nil {
		return err
	}
	var ingressFound bool
	for _, q := range qds {
		if i, ok := q.(*netlink.Ingress); ok {
			ingress = i
			ingressFound = true
			Debug.Printf("Found existing ingress qdisc %x\n", ingress.QdiscAttrs.Handle)
			break
		}
	}
	if !ingressFound {
		if err := netlink.QdiscAdd(ingress); err != nil {
			return fmt.Errorf("failed setting ingress qdisc: %v", err)
		}
		u32 := &netlink.U32{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: link.Attrs().Index,
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
	}
	return nil
}

func ensureFqCodelFd(link netlink.Link, fd int) error {
	fq := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
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
			LinkIndex: link.Attrs().Index,
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
