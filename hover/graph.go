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
	"io/ioutil"
	"math"

	"github.com/gonum/graph"
	"github.com/gonum/graph/encoding/dot"
	"github.com/gonum/graph/simple"
)

type Node interface {
	graph.Node
	FD() int
	Path() string
	ShortPath() string
	DOTID() string
	SetID(id int)
	NewInterfaceID() uint
	ReleaseInterfaceID(id uint)
}

type AdapterNode struct {
	adapter Adapter
	handles *HandlePool
}

func NewAdapterNode(adapter Adapter) *AdapterNode {
	return &AdapterNode{
		adapter: adapter,
		handles: NewHandlePool(MAX_INTERFACES),
	}
}

func (n *AdapterNode) ID() int           { return n.adapter.ID() }
func (n *AdapterNode) FD() int           { return n.adapter.FD() }
func (n *AdapterNode) DOTID() string     { return fmt.Sprintf("%q", n.ShortPath()) }
func (n *AdapterNode) Path() string      { return "modules/" + n.adapter.UUID() }
func (n *AdapterNode) ShortPath() string { return "m/" + n.adapter.UUID()[:8] }
func (n *AdapterNode) SetID(id int)      { n.adapter.SetID(id) }

func (n *AdapterNode) NewInterfaceID() uint {
	return n.handles.Acquire()
}
func (n *AdapterNode) ReleaseInterfaceID(id uint) {
	n.handles.Release(id)
}

type Edge struct {
	F, T     Node
	W        [3]uint
	FID, TID uint
}

func (e Edge) From() graph.Node { return e.F }
func (e Edge) To() graph.Node   { return e.T }
func (e Edge) Weight() float64  { return float64(e.W[0]) }
func (e Edge) Chain() [3]uint   { return e.W }
func (e Edge) FromID() uint     { return e.FID }
func (e Edge) ToID() uint       { return e.TID }

type Graph interface {
	graph.DirectedBuilder
	graph.NodeRemover
	Degree(graph.Node) int
	Node(int) graph.Node
}

func NewGraph() Graph {
	return simple.NewDirectedGraph(0, math.Inf(1))
}

func DumpDotFile(g Graph) {
	b, err := dot.Marshal(g, "dump", "", "  ", true)
	if err != nil {
		Error.Println(err)
		return
	}
	err = ioutil.WriteFile("/tmp/hover.dot", b, 0644)
	if err != nil {
		Error.Println(err)
	}
}
