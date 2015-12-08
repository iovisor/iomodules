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
	"io/ioutil"
	"strconv"
)

/*
#cgo LDFLAGS: -lbcc
#include <bcc/bpf_common.h>
#include <bcc/libbpf.h>
*/
import "C"

var (
	patchCode  string
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
	var b []byte
	b, err = ioutil.ReadFile(".patch.c")
	if err != nil {
		return
	}
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
	pp.adapter.bpf = NewBpfModule(string(b))
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
	err := p.modules.Delete(fmt.Sprintf("%d", adapter.Handle()))
	if err != nil {
		Warn.Printf("PatchPanel: error deleting module from table: %s\n", err)
	}
}

func (p *PatchPanel) Connect(a, b Adapter) (string, error) {
	id, err := NewUUID4()
	if err != nil {
		return "", err
	}
	if1, err := a.CreateInterface()
	if err != nil {
		return "", err
	}
	if2, err := b.CreateInterface()
	if err != nil {
		a.DeleteInterface(if1)
		return "", err
	}
	key := fmt.Sprintf("{%d %d %d 0}", a.Handle(), if1, 0)
	val := fmt.Sprintf("{%d %d 0 0}", b.Handle(), if2)
	p.links.Set(key, val)
	return id, nil
}
