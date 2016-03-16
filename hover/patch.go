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

type PatchPanel struct {
	adapter *BpfAdapter
	chainFd int
	modules AdapterTable
	kv      store.Store
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
		chainFd: -1,
		kv:      kv,
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
	pp.chainFd, err = pp.adapter.bpf.LoadNet("chain_pop")
	if err != nil {
		return
	}
	return
}

func (p *PatchPanel) Close() {
	if p.adapter != nil {
		p.adapter.Close()
	}
}

func (p *PatchPanel) FD() int {
	return p.chainFd
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
