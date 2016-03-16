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
	"github.com/gonum/graph/traverse"
)

type Node interface {
	graph.Node
	FD() int
	Path() string
	ShortPath() string
	DOTID() string
	SetID(id int)
	NewInterfaceID() (int, error)
	ReleaseInterfaceID(id int)
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

func (n *AdapterNode) NewInterfaceID() (int, error) {
	return n.handles.Acquire()
}
func (n *AdapterNode) ReleaseInterfaceID(id int) {
	n.handles.Release(id)
}

type Edge interface {
	graph.Edge
	F() Node
	T() Node
	FID() int
	TID() int
	Chain() [3]int
}

type EdgeChain struct {
	f, t     Node
	w        [3]int
	fid, tid int
}

func (e EdgeChain) From() graph.Node { return e.f }
func (e EdgeChain) To() graph.Node   { return e.t }
func (e EdgeChain) Weight() float64  { return float64(e.w[0]) }
func (e EdgeChain) F() Node          { return e.f }
func (e EdgeChain) T() Node          { return e.t }
func (e EdgeChain) Chain() [3]int    { return e.w }
func (e EdgeChain) FID() int         { return e.fid }
func (e EdgeChain) TID() int         { return e.tid }

type Graph interface {
	graph.DirectedBuilder
	graph.NodeRemover
	Degree(graph.Node) int
	Node(int) Node
	E(u, v graph.Node) Edge
}

type DirectedGraph struct {
	simple.DirectedGraph
}

func NewGraph() Graph {
	return &DirectedGraph{
		DirectedGraph: *simple.NewDirectedGraph(0, math.Inf(1)),
	}
}

func (g *DirectedGraph) Node(id int) Node       { return g.DirectedGraph.Node(id).(Node) }
func (g *DirectedGraph) E(u, v graph.Node) Edge { return g.Edge(u, v).(Edge) }

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

func NewDepthFirst(visit func(u, v Node), filter func(e Edge) bool) *traverse.DepthFirst {
	return &traverse.DepthFirst{
		Visit: func(u, v graph.Node) {
			visit(u.(Node), v.(Node))
		},
		EdgeFilter: func(e graph.Edge) bool {
			return filter(e.(Edge))
		},
	}
}

func NewBreadthFirst(visit func(u, v Node), filter func(e Edge) bool) *traverse.BreadthFirst {
	return &traverse.BreadthFirst{
		Visit: func(u, v graph.Node) {
			visit(u.(Node), v.(Node))
		},
		EdgeFilter: func(e graph.Edge) bool {
			return filter(e.(Edge))
		},
	}
}
