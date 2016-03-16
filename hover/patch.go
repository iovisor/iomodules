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

package hover

import (
	"fmt"
	"strconv"
	"strings"
	"syscall"

	"github.com/docker/libkv"
	"github.com/docker/libkv/store"
	"github.com/docker/libkv/store/boltdb"
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
	chainFd       int
	kfreeFd       int
	modules       AdapterTable
	links         AdapterTable
	moduleHandles *HandlePool
	kv            store.Store
}

func NewPatchPanel() (pp *PatchPanel, err error) {
	var id string
	id, err = NewUUID4()
	if err != nil {
		return
	}

	boltdb.Register()
	kv, err := libkv.NewStore(store.BOLTDB, []string{"/tmp/hover.db"}, &store.Config{Bucket: "patch"})
	if err != nil {
		Warn.Print(err)
		return
	}
	pp = &PatchPanel{
		tailcallFd:    -1,
		netdevRxFd:    -1,
		netdevTxFd:    -1,
		chainFd:       -1,
		moduleHandles: NewHandlePool(1024),
		kv:            kv,
	}
	defer func() {
		if err != nil {
			pp.Close()
			pp = nil
		}
	}()
	pp.adapter = &BpfAdapter{
		uuid:   id,
		name:   "patch",
		config: make(map[string]interface{}),
	}
	code := strings.Join([]string{iomoduleH, patchC}, "\n")
	pp.adapter.bpf = NewBpfModule(code, []string{"-w"})
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
	pp.netdevRxFd, err = pp.adapter.bpf.LoadNet("recv_netdev_ingress")
	if err != nil {
		return
	}
	pp.netdevTxFd, err = pp.adapter.bpf.LoadNet("recv_netdev_egress")
	if err != nil {
		return
	}
	pp.tailcallFd, err = pp.adapter.bpf.LoadNet("recv_tailcall")
	if err != nil {
		return
	}
	pp.chainFd, err = pp.adapter.bpf.LoadNet("chain_pop")
	if err != nil {
		return
	}
	pp.kfreeFd, err = pp.adapter.bpf.LoadKprobe("metadata_kfree_skbmem")
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
	return p.moduleHandles.Acquire(), nil
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
	return p.chainFd
}

func (p *PatchPanel) Register(adapter *BpfAdapter, handle uint, fd int) error {
	Info.Printf("PatchPanel: Registering module \"%s(%d)\"\n", adapter.Name(), handle)
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

	key1 := fmt.Sprintf("{%d %d 0 [0 0 0]}", adapterA.Handle(HandlerRx), if1.ID())
	val1 := fmt.Sprintf("{%d %d 0 0}", adapterB.Handle(HandlerRx), if2.ID())
	if err = p.links.Set(key1, val1); err != nil {
		return
	}
	defer func() {
		if err != nil {
			p.links.Delete(key1)
		}
	}()

	key2 := fmt.Sprintf("{%d %d 0 [0 0 0]}", adapterB.Handle(HandlerRx), if2.ID())
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

	k := fmt.Sprintf("{%d %d 0 [0 0 0]}", srcAdapter.Handle(HandlerRx), srcIfc.ID())
	v := fmt.Sprintf("{%d %d 0 0}", rcvAdapter.Handle(HandlerRx), rcvIfc.ID())
	if o, ok := p.links.Get(k); ok {
		k2 := fmt.Sprintf("{%d %d 0 [0 0 0]}", rcvAdapter.Handle(HandlerRx), rcvIfc.ID())
		v2 := o.(AdapterTablePair).Value
		Debug.Printf("existing link %s = %s\n", k, v2)
		if err = p.links.Set(k2, v2); err != nil {
			return
		}
	}
	if err = p.links.Set(k, v); err != nil {
		return
	}
	defer cleanupLinkIfError(k)

	k = fmt.Sprintf("{%d %d 1 [0 0 0]}", srcAdapter.Handle(HandlerRx), srcIfc.ID())
	v = fmt.Sprintf("{%d %d 0 0}", rcvAdapter.Handle(HandlerTx), rcvIfc.ID())
	Debug.Printf("tx link %s\n", v)
	if o, ok := p.links.Get(k); ok {
		k2 := fmt.Sprintf("{%d %d 1 [0 0 0]}", rcvAdapter.Handle(HandlerTx), rcvIfc.ID())
		v2 := o.(AdapterTablePair).Value
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
		if err = ensureEgressFd(link, p.netdevTxFd); err != nil {
			return
		}
	}

	{
		path := fmt.Sprintf("modules/%s/subscribed_policies/%s", rcvAdapter.ID(), newId)
		if err = p.kv.Put(path, []byte(newId), nil); err != nil {
			return
		}
	}

	{
		path := fmt.Sprintf("modules/%s/interfaces/%s/policies/%s", srcAdapter.ID(), srcIfc.Name(), newId)
		val := fmt.Sprintf("%s\n%s\n%s\n0", newId, rcvAdapter.ID(), rcvIfc.Name())
		if err = p.kv.Put(path, []byte(val), nil); err != nil {
			return
		}
	}

	id = newId
	return
}

func (p *PatchPanel) GetPolicies(srcAdapter Adapter, srcIfc Interface) (entries []*policyEntry, err error) {
	entries = []*policyEntry{}
	path := fmt.Sprintf("modules/%s/interfaces/%s/policies/", srcAdapter.ID(), srcIfc.Name())
	kvs, err := p.kv.List(path)
	if err != nil {
		return
	}
	for _, kv := range kvs {
		vals := strings.Split(string(kv.Value), "\n")
		if len(vals) != 4 {
			err = fmt.Errorf("Unable to parse Value in policies entry")
			return
		}
		entries = append(entries, &policyEntry{Id: vals[0], Module: vals[1]})
	}
	return
}

func ensureQdisc(link netlink.Link) (netlink.Qdisc, error) {
	qHandle := netlink.MakeHandle(0xffff, 0)
	qds, err := netlink.QdiscList(link)
	if err != nil {
		return nil, err
	}
	for _, q := range qds {
		if q.Attrs().Handle == qHandle {
			//Debug.Printf("Found existing ingress qdisc %x\n", q.Attrs().Handle)
			return q, nil
		}
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    qHandle,
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		return nil, fmt.Errorf("failed ensuring qdisc: %v", err)
	}
	return qdisc, nil
}

func ensureIngressFd(link netlink.Link, fd int) error {
	_, err := ensureQdisc(link)
	if err != nil {
		return err
	}
	fHandle := netlink.MakeHandle(0, 1)
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    fHandle,
			Priority:  1,
			Protocol:  syscall.ETH_P_ALL,
		},
		Fd:           fd,
		DirectAction: true,
	}
	filters, err := netlink.FilterList(link, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return fmt.Errorf("failed fetching ingress filter list: %s", err)
	}
	for _, f := range filters {
		if f.Attrs().Handle == fHandle {
			return nil
		}
	}
	if err := netlink.FilterAdd(filter); err != nil {
		return fmt.Errorf("failed adding ingress filter: %s", err)
	}
	//Debug.Printf("ensureIngressFd(%s) success\n", link.Attrs().Name)
	return nil
}

func ensureEgressFd(link netlink.Link, fd int) error {
	_, err := ensureQdisc(link)
	if err != nil {
		return err
	}
	fHandle := netlink.MakeHandle(0, 2)
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    fHandle,
			Priority:  1,
			Protocol:  syscall.ETH_P_ALL,
		},
		Fd:           fd,
		DirectAction: true,
	}
	filters, err := netlink.FilterList(link, netlink.HANDLE_MIN_EGRESS)
	if err != nil {
		return fmt.Errorf("failed fetching egress filter list: %s", err)
	}
	for _, f := range filters {
		if f.Attrs().Handle == fHandle {
			return nil
		}
	}
	if err := netlink.FilterAdd(filter); err != nil {
		return fmt.Errorf("failed adding egress filter: %v", err)
	}
	return nil
}
