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

package hover

import (
	"fmt"
	"strings"
)

func NewAdapter(req createModuleRequest, g Graph, id int) (adapter Adapter, err error) {
	uuid, err := NewUUID4()
	if err != nil {
		return
	}

	parts := strings.SplitN(req.ModuleType, "/", 2)
	switch parts[0] {
	case "bpf":
		a := &BpfAdapter{
			uuid:    uuid,
			name:    req.DisplayName,
			tags:    req.Tags,
			perm:    PermR | PermW,
			config:  make(map[string]interface{}),
			subtype: parts[1],
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
	SetConfig(req createModuleRequest, g Graph, id int) error
	Interfaces() <-chan Interface
	InterfaceByName(name string) Interface
	Tables() []map[string]interface{}
	Table(name string) AdapterTable
}

type AdapterTablePair struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type AdapterTable interface {
	ID() string
	Name() string
	Config() map[string]interface{}
	Get(key string) (interface{}, bool)
	Set(key, val string) error
	Delete(key string) error
	Iter() <-chan AdapterTablePair
}

type Interface interface {
	ID() int
	Name() string
}
