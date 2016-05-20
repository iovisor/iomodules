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

	"github.com/iovisor/iomodules/hover/bpf"
	"github.com/iovisor/iomodules/hover/canvas"
)

// NetlinkMonitor keeps track of the interfaces on this host. It can invoke a
// callback when an interface is added/deleted.
type NetlinkMonitor struct {
	// receive LinkUpdates from nl.Subscribe
	updates chan netlink.LinkUpdate

	// close(nlDone) to terminate Subscribe loop
	done  chan struct{}
	flush chan struct{}

	// nodes tracks netlink ifindex to graph Node mapping
	nodes map[int]*ExtInterface

	g       canvas.Graph
	r       *Renderer
	modules *bpf.BpfTable
	mtx     sync.RWMutex
}

func NewNetlinkMonitor(g canvas.Graph, r *Renderer, modules *bpf.BpfTable) (res *NetlinkMonitor, err error) {
	nlmon := &NetlinkMonitor{
		updates: make(chan netlink.LinkUpdate),
		done:    make(chan struct{}),
		flush:   make(chan struct{}),
		nodes:   make(map[int]*ExtInterface),
		g:       g,
		r:       r,
		modules: modules,
	}
	err = netlink.LinkSubscribe(nlmon.updates, nlmon.done)
	defer func() {
		if err != nil {
			nlmon.Close()
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
		nlmon.handleNewlink(link)
	}
	Debug.Println("NewNetlinkMonitor DONE")
	go nlmon.ParseLinkUpdates()
	res = nlmon
	return
}

func (nm *NetlinkMonitor) Close() {
	close(nm.done)
}

func (nm *NetlinkMonitor) ensureBridge(link *netlink.Bridge) canvas.Node {
	b := nm.g.NodeByPath("b:" + link.Attrs().Name)
	if b == nil {
		a := canvas.NewBridgeAdapter(link)
		node := canvas.NewAdapterNode(a)
		node.SetID(nm.g.NewNodeID())
		nm.g.AddNode(node)
		b = node
	}
	return b
}

func (nm *NetlinkMonitor) handleMasterChange(node *ExtInterface, link netlink.Link, isAdd bool) error {
	newMasterIdx := link.Attrs().MasterIndex
	Debug.Printf("link %s master %d\n", node.Link().Attrs().Name, newMasterIdx)
	if newMasterIdx != node.Link().Attrs().MasterIndex || isAdd {
		if newMasterIdx != 0 {
			// add case
			masterLink, err := netlink.LinkByIndex(newMasterIdx)
			if err != nil {
				return err
			}
			bridge, ok := masterLink.(*netlink.Bridge)
			if !ok {
				return fmt.Errorf("unsupported non-bridge master")
			}
			master := nm.ensureBridge(bridge)
			if node.ID() < 0 {
				node.SetID(nm.g.NewNodeID())
				nm.g.AddNode(node)
			}
			// set to 0 so that the normal egress path is taken
			fid, tid := 0, 0
			nm.g.SetEdge(canvas.NewEdgeChain(node, master, &fid, &tid))
			nm.g.SetEdge(canvas.NewEdgeChain(master, node, &tid, &fid))
			if err := nm.r.Provision(nm.g, []InterfaceNode{node}); err != nil {
				return err
			}
			if err := nm.ensureInterface(nm.g, node); err != nil {
				return err
			}
			nm.r.Run(nm.g, []InterfaceNode{node})
		} else {
			// remove case
		}
	}
	return nil
}

func (nm *NetlinkMonitor) handleNewlink(link netlink.Link) {
	nm.mtx.Lock()
	defer nm.mtx.Unlock()
	switch link := link.(type) {
	case *netlink.Bridge:
		nm.ensureBridge(link)
	default:
		if node, ok := nm.nodes[link.Attrs().Index]; ok {
			if err := nm.handleMasterChange(node, link, false); err != nil {
				Error.Println("Newlink failed master change", err)
				return
			}
			node.SetLink(link)
		} else {
			node := NewExtInterface(link)
			nm.nodes[link.Attrs().Index] = node
			if err := nm.handleMasterChange(node, link, true); err != nil {
				Error.Println("Newlink failed master change", err)
				return
			}
		}
	}
}

func (nm *NetlinkMonitor) handleDellink(link netlink.Link) {
	nm.mtx.Lock()
	defer nm.mtx.Unlock()
	switch link := link.(type) {
	case *netlink.Bridge:
		node := nm.g.NodeByPath("b:" + link.Attrs().Name)
		if node != nil {
			Warn.Println("TODO: remove resources for edges from " + node.Path())
			node.Close()
			nm.g.RemoveNode(node)
		}
	default:
		if _, ok := nm.nodes[link.Attrs().Index]; ok {
			delete(nm.nodes, link.Attrs().Index)
		}
	}
}

func (nm *NetlinkMonitor) ParseLinkUpdates() {
	for {
		select {
		case update, ok := <-nm.updates:
			if !ok {
				// channel closed
				Info.Printf("nm %p updates closed\n", nm)
				return
			}
			switch update.Header.Type {
			case syscall.RTM_NEWLINK:
				nm.handleNewlink(update.Link)
			case syscall.RTM_DELLINK:
				nm.handleDellink(update.Link)
			}
		case _ = <-nm.flush:
			// when nm.nodes is queried, ensures that all pending updates have been processed
		}
	}
}

func (nm *NetlinkMonitor) Interfaces() (nodes []InterfaceNode) {
	nm.flush <- struct{}{}
	nm.mtx.RLock()
	defer nm.mtx.RUnlock()
	for _, node := range nm.nodes {
		nodes = append(nodes, node)
	}
	return
}
func (nm *NetlinkMonitor) InterfaceByName(name string) (node InterfaceNode, err error) {
	nm.flush <- struct{}{}
	nm.mtx.RLock()
	defer nm.mtx.RUnlock()
	link, err := netlink.LinkByName(name)
	if err != nil {
		return
	}
	var ok bool
	if node, ok = nm.nodes[link.Attrs().Index]; !ok {
		err = fmt.Errorf("No interface %s found", name)
		return
	}
	return
}

func (nm *NetlinkMonitor) ensureInterface(g canvas.Graph, node InterfaceNode) error {
	if node.ID() < 0 {
		return nil
	}
	Info.Printf("visit: id=%d :: fd=%d :: %s :: %d\n", node.ID(), node.FD(), node.Path(), node.Link().Attrs().Index)
	nm.modules.Set(strconv.Itoa(node.ID()), strconv.Itoa(node.FD()))
	switch deg := g.Degree(node); deg {
	case 2:
		//Debug.Printf("Adding ingress for %s\n", node.Link().Attrs().Name)
		next := g.From(node)[0].(canvas.Node)
		e := g.E(node, next)
		if e.Serialize()[0] == 0 {
			return nil
		}
		chain, err := NewIngressChain(e.Serialize())
		if err != nil {
			return err
		}
		defer chain.Close()
		Info.Printf(" %4d: %-11s%s\n", e.F().Ifc(), next.Path(), e)
		if err := ensureIngressFd(node.Link(), chain.FD()); err != nil {
			return err
		}
	default:
		return fmt.Errorf("Invalid # edges for node %s, must be 2, got %d", node.Path(), deg)
	}
	return nil
}

func (nm *NetlinkMonitor) EnsureInterfaces(g canvas.Graph) {
	nm.flush <- struct{}{}
	nm.mtx.Lock()
	defer nm.mtx.Unlock()
	for _, node := range nm.nodes {
		if err := nm.ensureInterface(g, node); err != nil {
			panic(err)
		}
	}
}
