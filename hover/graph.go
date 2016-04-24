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
	return &AdapterNode{
		NodeBase: NewNodeBase(-1, adapter.FD(), adapter.UUID(), "", MAX_INTERFACES),
		adapter:  adapter,
	}
}

func (n *AdapterNode) SetID(id int)     { n.id = id }
func (n *AdapterNode) Close()           { n.adapter.Close() }
func (n *AdapterNode) Adapter() Adapter { return n.adapter }

type NodeIfc struct {
	node int
	ifc  int
}

func (ni NodeIfc) ID() int        { return ni.node }
func (ni NodeIfc) Ifc() int       { return ni.ifc }
func (ni NodeIfc) Serialize() int { return ni.ifc<<16 | ni.node }

type Edge interface {
	graph.Edge
	F() NodeIfc
	T() NodeIfc
	Update([]NodeIfc, int, int) bool
	ChainEquals([]NodeIfc) bool
	Serialize() [4]int
	ID() string
	MarkDeleted()
	IsDeleted() bool
}

type EdgeChain struct {
	id             string
	f, t           Node
	w              [3]NodeIfc
	fromIfc, toIfc *int
	dirty          bool
	deleted        bool
}

func NewEdgeChain(f, t Node, fp, tp *int) *EdgeChain {
	return &EdgeChain{
		id:      encrypter.EncodePair(f.ID(), t.ID()),
		f:       f,
		t:       t,
		w:       [3]NodeIfc{},
		fromIfc: fp,
		toIfc:   tp,
	}
}
func (e *EdgeChain) ID() string       { return e.id }
func (e *EdgeChain) From() graph.Node { return e.f }
func (e *EdgeChain) To() graph.Node   { return e.t }
func (e *EdgeChain) F() NodeIfc       { return NodeIfc{e.f.ID(), *e.fromIfc} }
func (e *EdgeChain) T() NodeIfc       { return NodeIfc{e.t.ID(), *e.toIfc} }
func (e *EdgeChain) Weight() float64  { return float64(2) }
func (e *EdgeChain) MarkDeleted()     { e.deleted = true }
func (e *EdgeChain) IsDeleted() bool  { return e.deleted }

func (e *EdgeChain) ChainEquals(dst []NodeIfc) bool {
	if len(e.w) != len(dst) {
		return false
	}
	for i, v := range e.w {
		if dst[i] != v {
			return false
		}
	}
	return true
}
func (e *EdgeChain) Update(chain []NodeIfc, fromIfc, toIfc int) bool {
	if !e.ChainEquals(chain) {
		if len(chain) > len(e.w) {
			panic("EdgeChain.Update: chain too long")
		}
		for i, _ := range e.w {
			e.w[i] = NodeIfc{}
		}
		for i, v := range chain {
			e.w[i] = v
		}
		e.dirty = true
	}
	if *e.fromIfc != fromIfc {
		*e.fromIfc = fromIfc
		e.dirty = true
	}
	if *e.toIfc != toIfc {
		*e.toIfc = toIfc
		e.dirty = true
	}
	return e.dirty
}

func (e *EdgeChain) serialize() [4]int {
	buf := [4]int{}
	if e.deleted {
		return buf
	}
	chain := buf[:0]
	for _, ni := range e.w {
		if ni.Ifc() == 0 {
			break
		}
		chain = append(chain, ni.Serialize())
	}
	if *e.toIfc > 0 {
		chain = append(chain, NodeIfc{e.t.ID(), *e.toIfc}.Serialize())
	}
	return buf
}
func (e *EdgeChain) Serialize() [4]int {
	e.dirty = false
	return e.serialize()
}
func (e *EdgeChain) String() string {
	// compatible with scanf bcc key reader
	return fmt.Sprintf("{%#x}", e.serialize())
}

type Graph interface {
	graph.Directed
	graph.NodeAdder
	graph.NodeRemover
	SetEdge(Edge)
	RemoveEdge(Edge)
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

func (g *DirectedGraph) Copy(src Graph) {
	g.DirectedGraph = *simple.NewDirectedGraph(0, math.Inf(1))
	graph.Copy(&g.DirectedGraph, src)
	g.paths = make(map[string]int)
	for k, v := range src.(*DirectedGraph).paths {
		g.paths[k] = v
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

func (g *DirectedGraph) SetEdge(e Edge) {
	g.DirectedGraph.SetEdge(e)
}
func (g *DirectedGraph) RemoveEdge(e Edge) {
	g.DirectedGraph.RemoveEdge(e)
}

func (g *DirectedGraph) AddNode(node graph.Node) {
	Debug.Printf("AddNode %s\n", node.(Node).Path())
	g.DirectedGraph.AddNode(node)
	g.paths[node.(Node).Path()] = node.ID()
}
func (g *DirectedGraph) RemoveNode(node graph.Node) {
	Debug.Printf("RemoveNode %s\n", node.(Node).Path())
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
