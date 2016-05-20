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

package hover

import (
	"fmt"
	"syscall"

	"github.com/vishvananda/netlink"

	"github.com/iovisor/iomodules/hover/bpf"
	"github.com/iovisor/iomodules/hover/canvas"
)

type InterfaceNode interface {
	canvas.Node
	Link() netlink.Link
	SetLink(netlink.Link)
}

type ExtInterface struct {
	canvas.NodeBase
	link netlink.Link
}

func NewExtInterface(link netlink.Link) *ExtInterface {
	return &ExtInterface{
		NodeBase: canvas.NewNodeBase(-1, -1, link.Attrs().Name, "i:", 1),
		link:     link,
	}
}

func (ifc *ExtInterface) FD() int {
	if ifc.NodeBase.FD() >= 0 {
		return ifc.NodeBase.FD()
	}
	cflags := []string{
		fmt.Sprintf("-DINTERFACE_ID=%d", ifc.link.Attrs().Index),
	}
	bpf := bpf.NewBpfModule(bpf.NetdevTxC, cflags)
	if bpf == nil {
		panic(fmt.Errorf("Failed to compile bpf module for %s egress", ifc.Path()))
	}
	// free the llvm memory, just keep the fd
	defer bpf.Close()
	fd, err := bpf.LoadNet("egress")
	if err != nil {
		panic(err)
	}
	fd2, err := syscall.Dup(fd)
	if err != nil {
		panic(err)
	}
	ifc.NodeBase.SetFD(fd2)
	return ifc.NodeBase.FD()
}

func (ifc *ExtInterface) Link() netlink.Link        { return ifc.link }
func (ifc *ExtInterface) SetLink(link netlink.Link) { ifc.link = link }
func (ifc *ExtInterface) SetID(id int)              { ifc.NodeBase.SetID(id) }

type IngressChain struct {
	fd int
}

func NewIngressChain(chain [4]int) (*IngressChain, error) {
	cflags := []string{
		fmt.Sprintf("-DCHAIN_VALUE0=%#x", chain[0]),
		fmt.Sprintf("-DCHAIN_VALUE1=%#x", chain[1]),
		fmt.Sprintf("-DCHAIN_VALUE2=%#x", chain[2]),
		fmt.Sprintf("-DCHAIN_VALUE3=%#x", chain[3]),
	}
	//Debug.Printf("netdev: %v\n", cflags)
	bpf := bpf.NewBpfModule(bpf.NetdevRxC, cflags)
	if bpf == nil {
		return nil, fmt.Errorf("NewIngressChain bpf compile failed")
	}
	defer bpf.Close()
	fd, err := bpf.LoadNet("ingress")
	if err != nil {
		return nil, err
	}
	fd2, err := syscall.Dup(fd)
	if err != nil {
		return nil, err
	}
	return &IngressChain{fd: fd2}, nil
}

func (c *IngressChain) Close()  { syscall.Close(c.fd) }
func (c *IngressChain) FD() int { return c.fd }

type EgressChain struct {
	fd int
}

func NewEgressChain(chain [4]int) (*EgressChain, error) {
	cflags := []string{
		fmt.Sprintf("-DCHAIN_VALUE0=%#x", chain[0]),
		fmt.Sprintf("-DCHAIN_VALUE1=%#x", chain[1]),
		fmt.Sprintf("-DCHAIN_VALUE2=%#x", chain[2]),
		fmt.Sprintf("-DCHAIN_VALUE3=%#x", chain[3]),
	}
	//Debug.Printf("netdev: %v\n", cflags)
	bpf := bpf.NewBpfModule(bpf.NetdevEgressC, cflags)
	if bpf == nil {
		return nil, fmt.Errorf("NewEgressChain bpf compile failed")
	}
	defer bpf.Close()
	fd, err := bpf.LoadNet("egress")
	if err != nil {
		return nil, err
	}
	fd2, err := syscall.Dup(fd)
	if err != nil {
		return nil, err
	}
	return &EgressChain{fd: fd2}, nil
}

func (c *EgressChain) Close()  { syscall.Close(c.fd) }
func (c *EgressChain) FD() int { return c.fd }
