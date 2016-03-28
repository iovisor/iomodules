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
	"golang.org/x/tools/container/intsets"
)

type Node interface {
	graph.Node
	FD() int
	String() string
	Path() string
	DOTID() string
	SetID(id int)
	NewInterfaceID() (int, error)
	ReleaseInterfaceID(id int)
	Groups() *intsets.Sparse
	Close()
}

type NodeBase struct {
	id      int
	fd      int
	uuid    string
	prefix  string
	handles *HandlePool
	groups  *intsets.Sparse
}

func NewNodeBase(id, fd int, uuid, prefix string, nhandles uint) NodeBase {
	return NodeBase{
		id:      id,
		fd:      fd,
		uuid:    uuid,
		prefix:  prefix,
		handles: NewHandlePool(nhandles),
		groups:  &intsets.Sparse{},
	}
}

func (n *NodeBase) ID() int                      { return n.id }
func (n *NodeBase) FD() int                      { return n.fd }
func (n *NodeBase) DOTID() string                { return fmt.Sprintf("%q", n.Path()) }
func (n *NodeBase) Path() string                 { return n.prefix + n.uuid }
func (n *NodeBase) String() string               { return n.Path() }
func (n *NodeBase) Groups() *intsets.Sparse      { return n.groups }
func (n *NodeBase) NewInterfaceID() (int, error) { return n.handles.Acquire() }
func (n *NodeBase) ReleaseInterfaceID(id int)    { n.handles.Release(id) }
func (n *NodeBase) Close()                       {}

type AdapterNode struct {
	NodeBase
	adapter Adapter
}

func NewAdapterNode(adapter Adapter) *AdapterNode {
	var prefix string
	switch adapter.(type) {
	case *BridgeAdapter:
		prefix = "b/"
	default:
		prefix = "m/"
	}
	return &AdapterNode{
		NodeBase: NewNodeBase(-1, adapter.FD(), adapter.UUID(), prefix, MAX_INTERFACES),
		adapter:  adapter,
	}
}

func (n *AdapterNode) SetID(id int) { n.id = id }
func (n *AdapterNode) Close()       { n.adapter.Close() }

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
	HasPath(path string) bool
	NodeByPath(path string) Node
}

type DirectedGraph struct {
	simple.DirectedGraph
	paths map[string]int
}

func NewGraph() Graph {
	return &DirectedGraph{
		DirectedGraph: *simple.NewDirectedGraph(0, math.Inf(1)),
		paths:         make(map[string]int),
	}
}

func (g *DirectedGraph) Node(id int) Node       { return g.DirectedGraph.Node(id).(Node) }
func (g *DirectedGraph) E(u, v graph.Node) Edge { return g.Edge(u, v).(Edge) }

func (g *DirectedGraph) NodeByPath(path string) Node {
	if id, ok := g.paths[path]; ok {
		return g.DirectedGraph.Node(id).(Node)
	}
	return nil
}

func (g *DirectedGraph) HasPath(path string) bool {
	if id, ok := g.paths[path]; ok {
		return g.Has(simple.Node(id))
	}
	return false
}

func (g *DirectedGraph) AddNode(node graph.Node) {
	g.DirectedGraph.AddNode(node)
	g.paths[node.(Node).Path()] = node.ID()
}
func (g *DirectedGraph) RemoveNode(node graph.Node) {
	g.DirectedGraph.RemoveNode(node)
	delete(g.paths, node.(Node).Path())
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
