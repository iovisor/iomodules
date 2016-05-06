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

	"golang.org/x/tools/container/intsets"
)

type Renderer struct {
}

func NewRenderer() *Renderer {
	return &Renderer{}
}

func filterInterfaceNode(e Edge) bool {
	_, ok := e.To().(InterfaceNode)
	return !ok
}

func computeChainFrom(from, to Node) (chain []NodeIfc) {
	// For each link, there is a chain of modules to be invoked: the
	// ingress policy modules, the egress policy modules, and the final
	// forwarding nexthop.
	//
	// To compute the chain in each direction, the following algorithm is
	// followed:
	//  Let T and F represent the set of groups for the 'to' and 'from'
	//   nodes, respectively.
	//  The leaving set L is the set difference between F and T.
	//  L := F - T
	//  The entering set E is the set difference between T and F
	//  E := T - F
	//
	// For the directed edge from:to, the chain is built as follows:
	//  For each module e in E, invoke the ingress policy (e.ifc[1])
	//  For each module l in L, invoke the egress policy (l.ifc[2])
	//
	// The directed edge to:from is calculated by calling this function
	// with to/from reversed.

	var e, l, x intsets.Sparse
	l.Difference(from.Groups(), to.Groups())
	e.Difference(to.Groups(), from.Groups())

	var id int

	x.Copy(&e)
	for x.TakeMin(&id) {
		chain = append(chain, NodeIfc{id, 1})
	}
	x.Copy(&l)
	for x.TakeMin(&id) {
		chain = append(chain, NodeIfc{id, 2})
	}
	return chain
}

// provisionNode allocates the IDs for one node, meant to be called from a tree
// traversal. If allocation fails, panic and expect to be recovered. The
// allocated IDs are stored in newIds so as to be collected in the recover
// routine.
func provisionNode(g Graph, this Node, newIds *[]NodeIfc) {
	Info.Printf("Provisioning %s (%d)\n", this, this.ID())
	for _, t := range g.From(this) {
		e := g.E(this, t)
		target := t.(Node)
		chain := computeChainFrom(this, target)
		fid, tid := e.F().Ifc(), e.T().Ifc()
		var err error
		if fid < 0 {
			if fid, err = e.From().(Node).NewInterfaceID(); err != nil {
				Error.Printf("Provisioning %s failed %s\n", e.From().(Node), err)
				panic(err)
			}
			*newIds = append(*newIds, NodeIfc{e.From().ID(), fid})
		}
		if tid < 0 {
			if tid, err = e.To().(Node).NewInterfaceID(); err != nil {
				Error.Printf("Provisioning %s failed %s\n", e.To().(Node), err)
				panic(err)
			}
			*newIds = append(*newIds, NodeIfc{e.To().ID(), tid})
		}
		if e.Update(chain, fid, tid) {
		}
	}
}

func (h *Renderer) Provision(g Graph, nlmon *NetlinkMonitor) (err error) {
	newIds := []NodeIfc{}
	visitFn := func(prev, this Node) {
		provisionNode(g, this, &newIds)
	}
	t := NewDepthFirst(visitFn, filterInterfaceNode)

	defer func() {
		if r := recover(); r != nil {
			switch r := r.(type) {
			case error:
				err = r
				for _, ni := range newIds {
					g.Node(ni.ID()).ReleaseInterfaceID(ni.Ifc())
				}
				// rollback
			default:
				panic(r)
			}
		}
	}()

	// Find all of the Adapter (internal) nodes reachable from an external interface.
	// Collect the ID of each node and update the modules table.
	for _, node := range nlmon.Interfaces() {
		if node.ID() < 0 {
			continue
		}
		provisionNode(g, node, &newIds)
		t.Walk(g, node, nil)
	}
	return
}

func (h *Renderer) Run(g Graph, pp *PatchPanel, nlmon *NetlinkMonitor) {
	for _, node := range g.Nodes() {
		if node, ok := node.(Node); ok && node.FD() >= 0 {
			pp.modules.Set(strconv.Itoa(node.ID()), strconv.Itoa(node.FD()))
			//Info.Printf("modules[%d] = %d\n", node.ID(), node.FD())
		}
	}
	visitFn := func(prev, this Node) {
		//pp.modules.Set(strconv.Itoa(this.ID()), strconv.Itoa(this.FD()))
		Info.Printf("visit: %d :: %s\n", this.ID(), this.Path())
		for _, t := range g.From(this) {
			e := g.E(this, t)
			adapter := this.(*AdapterNode).adapter
			target := t.(Node)
			if adapter.Type() == "bridge" {
				if target, ok := target.(*ExtInterface); ok {
					if e.Serialize()[0] == 0 {
						continue
					}
					chain, err := NewEgressChain(e.Serialize())
					if err != nil {
						panic(err)
					}
					defer chain.Close()
					Info.Printf(" %4d: %-11s%s\n", e.F().Ifc(), target.Path(), e)
					if err := ensureEgressFd(target.Link(), chain.FD()); err != nil {
						panic(err)
					}
				}
			} else {
				fc := adapter.Table("forward_chain")
				if fc == nil {
					panic(fmt.Errorf("Could not find forward_chain in adapter"))
				}
				key := fmt.Sprintf("%d", e.F().Ifc())
				val := fmt.Sprintf("{%#x}", e.Serialize())
				Info.Printf(" %4s: %-11s%s\n", key, target.Path(), val)
				if err := fc.Set(key, val); err != nil {
					panic(err)
				}
				//Debug.Printf(" %s:%d -> %s:%d\n", this.Path(), i, target.Path(), target.ID())
			}
			if e.IsDeleted() {
				g.RemoveEdge(e)
			}
		}
	}
	t := NewDepthFirst(visitFn, filterInterfaceNode)
	// Find all of the Adapter (internal) nodes reachable from an external interface.
	// Collect the ID of each node and update the modules table.
	for _, node := range nlmon.Interfaces() {
		if node.ID() < 0 {
			continue
		}
		t.Walk(g, node, nil)
	}
}
