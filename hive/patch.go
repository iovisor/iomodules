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
	netdevFd      int
	modules       AdapterTable
	links         AdapterTable
	moduleHandles *HandlePool
}

func NewPatchPanel() (pp *PatchPanel, err error) {
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
	pp.adapter.bpf = NewBpfModule(strings.Join([]string{iomoduleH, patchC}, "\n"))
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
