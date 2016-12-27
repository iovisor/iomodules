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

	"golang.org/x/tools/container/intsets"

	"github.com/iovisor/iomodules/hover/canvas"
	"github.com/iovisor/iomodules/hover/util"
)

var (
	Debug = util.Debug
	Info  = util.Info
	Warn  = util.Warn
	Error = util.Error
)

type Renderer struct {
}

func NewRenderer() *Renderer {
	return &Renderer{}
}

func filterInterfaceNode(e canvas.Edge) bool {
	_, ok := e.To().(InterfaceNode)
	return !ok
}

func computeChainFrom(from, to canvas.Node) (chain []canvas.NodeIfc) {
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
		chain = append(chain, canvas.NodeIfc{id, 1})
	}
	x.Copy(&l)
	for x.TakeMin(&id) {
		chain = append(chain, canvas.NodeIfc{id, 2})
	}
	return chain
}

// provisionNode allocates the IDs for one node, meant to be called from a tree
// traversal. If allocation fails, panic and expect to be recovered. The
// allocated IDs are stored in newIds so as to be collected in the recover
// routine.
func provisionNode(g canvas.Graph, this canvas.Node, newIds *[]canvas.NodeIfc) {
	Info.Printf("Provisioning %s (%d)\n", this, this.ID())
	for _, t := range g.From(this) {
		e := g.E(this, t)
		target := t.(canvas.Node)
		chain := computeChainFrom(this, target)
		fid, tid := e.F().Ifc(), e.T().Ifc()
		var err error
		if fid < 0 {
			if fid, err = e.From().(canvas.Node).NewInterfaceID(); err != nil {
				Error.Printf("Provisioning %s failed %s\n", e.From().(canvas.Node), err)
				panic(err)
			}
			*newIds = append(*newIds, canvas.NodeIfc{e.From().ID(), fid})
		}
		if tid < 0 {
			if tid, err = e.To().(canvas.Node).NewInterfaceID(); err != nil {
				Error.Printf("Provisioning %s failed %s\n", e.To().(canvas.Node), err)
				panic(err)
			}
			*newIds = append(*newIds, canvas.NodeIfc{e.To().ID(), tid})
		}
		if e.Update(chain, fid, tid) {
		}
	}
}

func (h *Renderer) Provision(g canvas.Graph, nodes []InterfaceNode) (err error) {
	newIds := []canvas.NodeIfc{}

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
	for _, node := range nodes {
		if node.ID() < 0 {
			continue
		}
		provisionNode(g, node, &newIds)
	}

	for _, node:= range g.Nodes() {
		provisionNode(g, node.(canvas.Node), &newIds)
	}

	return
}

func (h *Renderer) Run(g canvas.Graph, nodes []InterfaceNode) {
	visitFn := func(prev, this canvas.Node) {
		Info.Printf("visit: %d :: %s\n", this.ID(), this.Path())
		for _, t := range g.From(this) {
			e := g.E(this, t)
			adapter := this.(*canvas.AdapterNode).Adapter()
			if e.IsDeleted() {
				fc := adapter.Table("forward_chain")
				if fc == nil {
					panic(fmt.Errorf("Could not find forward_chain in adapter"))
				}

				// find and delete the reverse edge as well
				e2 := g.E(t, this)
				if !e2.IsDeleted() {
					panic(fmt.Errorf("Reverse edge %d->%d is not deleted", t.ID(), this.ID()))
				}

				// clear previous entry (if any) in the ifc table
				key := fmt.Sprintf("%d", e.F().Ifc())
				if err := fc.Set(key, "{ [ 0x0 0x0 0x0 0x0 ] }"); err != nil {
					panic(err)
				}

				g.RemoveEdge(e)
				g.RemoveEdge(e2)

				// do not perform any further processing on node 't'
				continue
			}
			target := t.(canvas.Node)
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
		}
	}
	t := canvas.NewDepthFirst(visitFn, filterInterfaceNode)
	// Find all of the Adapter (internal) nodes reachable from an external interface.
	// Collect the ID of each node and update the modules table.
	for _, node := range nodes {
		if node.ID() < 0 {
			continue
		}
		t.Walk(g, node, nil)
	}


	// reset interfaces with degree 0; these interfaces are now unreachable
	for _, node := range nodes {
		//Debug.Printf("Run cleanup: considering node %d\n", node.ID())
		if node.ID() < 0 {
			continue
		}
		degree := g.Degree(node)
		//Debug.Printf("Run cleanup: node %d has degree %d\n", node.ID(), degree)
		if degree != 0 {
			continue
		}
		g.RemoveNode(node)

		// release and reset ID allocated for this interface
		node.ReleaseInterfaceID(node.ID())
		node.SetID(-1)
	}

}
