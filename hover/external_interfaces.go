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
	"strconv"
	"sync"
	"syscall"

	"github.com/vishvananda/netlink"
)

type InterfaceNode interface {
	Node
	Link() netlink.Link
}

type ExtInterface struct {
	id      int
	link    netlink.Link
	fd      int
	handles *HandlePool
}

func NewExtInterface(link netlink.Link) *ExtInterface {
	return &ExtInterface{
		id:      -1,
		link:    link,
		fd:      -1,
		handles: NewHandlePool(1),
	}
}

func (ifc *ExtInterface) FD() int {
	if ifc.fd >= 0 {
		return ifc.fd
	}
	cflags := []string{
		fmt.Sprintf("-DINTERFACE_ID=%d", ifc.link.Attrs().Index),
	}
	bpf := NewBpfModule(netdevTxC, cflags)
	if bpf == nil {
		panic(fmt.Errorf("Failed to compile bpf module for %s egress", ifc.ShortPath()))
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
	ifc.fd = fd2
	return ifc.fd
}

func (ifc *ExtInterface) ID() int                      { return ifc.id }
func (ifc *ExtInterface) DOTID() string                { return fmt.Sprintf("%q", ifc.ShortPath()) }
func (ifc *ExtInterface) Link() netlink.Link           { return ifc.link }
func (ifc *ExtInterface) Path() string                 { return "external_interfaces/" + ifc.link.Attrs().Name }
func (ifc *ExtInterface) ShortPath() string            { return "e/" + ifc.link.Attrs().Name }
func (ifc *ExtInterface) SetID(id int)                 { ifc.id = id }
func (ifc *ExtInterface) NewInterfaceID() (int, error) { return ifc.handles.Acquire() }
func (ifc *ExtInterface) ReleaseInterfaceID(id int)    { ifc.handles.Release(id) }

type IngressChain struct {
	fd int
}

func NewIngressChain(chain [3]int) (*IngressChain, error) {
	cflags := []string{
		fmt.Sprintf("-DCHAIN_VALUE0=0x%x", chain[0]),
		fmt.Sprintf("-DCHAIN_VALUE1=0x%x", chain[1]),
		fmt.Sprintf("-DCHAIN_VALUE2=0x%x", chain[2]),
	}
	//Debug.Printf("netdev: %v\n", cflags)
	bpf := NewBpfModule(netdevRxC, cflags)
	if bpf == nil {
		return nil, fmt.Errorf("could not compile bpf module for external interface")
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

// HostMonitor keeps track of the interfaces on this host. It can invoke a
// callback when an interface is added/deleted.
type HostMonitor struct {
	// receive LinkUpdates from nl.Subscribe
	updates chan netlink.LinkUpdate

	// close(nlDone) to terminate Subscribe loop
	done  chan struct{}
	flush chan struct{}

	// nodes tracks netlink ifindex to graph Node mapping
	nodes map[int32]*ExtInterface

	g   Graph
	mtx sync.RWMutex
}

func NewHostMonitor(g Graph) (res *HostMonitor, err error) {
	hmon := &HostMonitor{
		updates: make(chan netlink.LinkUpdate),
		done:    make(chan struct{}),
		flush:   make(chan struct{}),
		nodes:   make(map[int32]*ExtInterface),
		g:       g,
	}
	err = netlink.LinkSubscribe(hmon.updates, hmon.done)
	defer func() {
		if err != nil {
			hmon.Close()
		}
	}()
	if err != nil {
		return
	}
	links, err := netlink.LinkList()
	if err != nil {
		return
	}
	for _, link := range links {
		hmon.nodes[int32(link.Attrs().Index)] = NewExtInterface(link)
	}
	Debug.Println("NewHostMonitor DONE")
	go hmon.ParseLinkUpdates()
	res = hmon
	return
}

func (h *HostMonitor) Close() {
	close(h.done)
}

func (h *HostMonitor) ParseLinkUpdates() {
	for {
		select {
		case update, ok := <-h.updates:
			if !ok {
				// channel closed
				return
			}
			h.mtx.Lock()
			switch update.Header.Type {
			case syscall.RTM_NEWLINK:
				if _, ok := h.nodes[update.Index]; !ok {
					h.nodes[update.Index] = NewExtInterface(update.Link)
				}
			case syscall.RTM_DELLINK:
				if node, ok := h.nodes[update.Index]; ok {
					_ = node
					delete(h.nodes, update.Index)
				}
			}
			h.mtx.Unlock()
		case _ = <-h.flush:
			// when h.nodes is queried, ensures that all pending updates have been processed
		}
	}
}

func (h *HostMonitor) Interfaces() (nodes []InterfaceNode) {
	h.flush <- struct{}{}
	h.mtx.RLock()
	defer h.mtx.RUnlock()
	for _, node := range h.nodes {
		nodes = append(nodes, node)
	}
	return
}
func (h *HostMonitor) InterfaceByName(name string) (node InterfaceNode, err error) {
	h.flush <- struct{}{}
	h.mtx.RLock()
	defer h.mtx.RUnlock()
	link, err := netlink.LinkByName(name)
	if err != nil {
		return
	}
	var ok bool
	if node, ok = h.nodes[int32(link.Attrs().Index)]; !ok {
		err = fmt.Errorf("No interface %s found", name)
		return
	}
	return
}

func (h *HostMonitor) EnsureInterfaces(g Graph, pp *PatchPanel) {
	h.flush <- struct{}{}
	h.mtx.Lock()
	defer h.mtx.Unlock()
	for ifindex, node := range h.nodes {
		if node.ID() < 0 {
			continue
		}
		Info.Printf("visit: %d :: %s :: %d\n", node.ID(), node.ShortPath(), ifindex)
		pp.modules.Set(strconv.Itoa(node.ID()), strconv.Itoa(node.FD()))
		switch deg := g.Degree(node); deg {
		case 2:
			//Debug.Printf("Adding ingress for %s\n", node.Link().Attrs().Name)
			next := g.From(node)[0]
			e := g.Edge(node, next).(Edge)
			chain, err := NewIngressChain(e.Chain())
			if err != nil {
				panic(err)
			}
			defer chain.Close()
			Info.Printf(" %4d: %-11s{%#x}\n", e.FromID(), next.(Node).ShortPath(), e.Chain())
			if err := ensureIngressFd(node.Link(), chain.FD()); err != nil {
				panic(err)
			}
		default:
			panic(fmt.Errorf("Invalid # edges for node %s, must be 2, got %d", node.Path(), deg))
		}
	}
}
