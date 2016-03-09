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
	"math"

	"github.com/gonum/graph"
	"github.com/gonum/graph/simple"
)

type Node struct {
	adapter Adapter
	id      int
}

func (n Node) ID() int {
	return n.id
}

type Edge struct {
	F, T graph.Node
	W    float64
}

func (e Edge) From() graph.Node { return e.F }
func (e Edge) To() graph.Node   { return e.T }
func (e Edge) Weight() float64  { return e.W }

type Graph interface {
	graph.Graph
}

func NewGraph() Graph {
	return simple.NewDirectedGraph(0, math.Inf(1))
}
