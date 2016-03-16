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

func (h *Renderer) Provision(g Graph, pp *PatchPanel, hmon *HostMonitor) {
	visitFn := func(prev, this Node) {
		for i, n := range g.From(this) {
			target := n.(Node)
			pp.modules.Set(strconv.Itoa(i), strconv.Itoa(target.ID()))
			Debug.Printf(" %s:%d -> %s:%d\n", this.Path(), i, target.Path(), target.ID())
		}
	}
	t := NewDepthFirst(visitFn, filterInterfaceNode)
	// Find all of the Adapter (internal) nodes reachable from an external interface.
	// Collect the ID of each node and update the modules table.
	for _, node := range hmon.Interfaces() {
		if !g.Has(node) {
			continue
		}
		t.Walk(g, node, nil)
	}
}

func (h *Renderer) Run(g Graph, pp *PatchPanel, hmon *HostMonitor) {
	visitFn := func(prev, this Node) {
		pp.modules.Set(strconv.Itoa(this.ID()), strconv.Itoa(this.FD()))
		Info.Printf("visit: %d :: %s\n", this.ID(), this.ShortPath())
		for _, t := range g.From(this) {
			e := g.Edge(this, t).(Edge)
			adapter := this.(*AdapterNode).adapter
			target := t.(Node)
			fc := adapter.Table("forward_chain")
			if fc == nil {
				panic(fmt.Errorf("Could not find forward_chain in adapter"))
			}
			key := fmt.Sprintf("%d", e.FromID())
			val := fmt.Sprintf("{%#x}", e.Chain())
			Info.Printf(" %4s: %-11s%s\n", key, target.ShortPath(), val)
			if err := fc.Set(key, val); err != nil {
				panic(err)
			}
			//Debug.Printf(" %s:%d -> %s:%d\n", this.Path(), i, target.Path(), target.ID())
		}
	}
	t := NewDepthFirst(visitFn, filterInterfaceNode)
	// Find all of the Adapter (internal) nodes reachable from an external interface.
	// Collect the ID of each node and update the modules table.
	for _, node := range hmon.Interfaces() {
		if node.ID() < 0 {
			continue
		}
		t.Walk(g, node, nil)
	}
}
