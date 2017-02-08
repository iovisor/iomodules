// Copyright 2015 PLUMgrid
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

// vim: set ts=8:sts=8:sw=8:noet

package canvas

import (
	"fmt"
	"strings"

	"github.com/iovisor/iomodules/hover/api"
	"github.com/iovisor/iomodules/hover/bpf"
	"github.com/iovisor/iomodules/hover/util"
)

var (
	Debug = util.Debug
	Info  = util.Info
	Warn  = util.Warn
	Error = util.Error
)

const (
	PermW = 1 << (1 + iota)
	PermR
)

type Adapter interface {
	UUID() string
	FD() int
	Close()
	Type() string
	Name() string
	Tags() []string
	Perm() uint
	Config() map[string]interface{}
	SetConfig(req api.ModuleBase, g Graph, id int) error
	Tables() []map[string]interface{}
	Table(name string) AdapterTable
}

type AdapterTable interface {
	ID() string
	Name() string
	Config() map[string]interface{}
	Get(key string) (interface{}, bool)
	Set(key, val string) error
	Delete(key string) error
	Iter() <-chan api.ModuleTableEntry
}

type Interface interface {
	ID() int
	Name() string
}

type AdapterNode struct {
	NodeBase
	adapter Adapter
}

func NewAdapter(req api.ModuleBase, g Graph, id int) (adapter Adapter, err error) {
	uuid := fmt.Sprintf("%08d", id)

	parts := strings.SplitN(req.ModuleType, "/", 2)
	switch parts[0] {
	case "bpf":
		var subtype string
		if len(parts) > 1 {
			subtype = parts[1]
		}
		a := &BpfAdapter{
			uuid:    uuid,
			perm:    PermR | PermW,
			config:  make(map[string]interface{}),
			subtype: subtype,
		}
		if err = a.SetConfig(req, g, id); err != nil {
			return
		}
		adapter = a
	case "bridge":
		a := &BridgeAdapter{
			uuid:   uuid,
			name:   req.DisplayName,
			tags:   req.Tags,
			perm:   PermR | PermW,
			config: make(map[string]interface{}),
		}
		if err = a.SetConfig(req, g, id); err != nil {
			return
		}
		adapter = a
	default:
		err = fmt.Errorf("unknown ModuleType %s", req.ModuleType)
		return
	}
	return
}

func NewAdapterNode(adapter Adapter) *AdapterNode {
	return &AdapterNode{
		NodeBase: NewNodeBase(-1, adapter.FD(), adapter.UUID(), "", bpf.MAX_INTERFACES),
		adapter:  adapter,
	}
}

func (n *AdapterNode) Close()           { n.adapter.Close() }
func (n *AdapterNode) Adapter() Adapter { return n.adapter }
