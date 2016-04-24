// Copyright 2015-2016 PLUMgrid
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

type BpfAdapter struct {
	uuid    string
	name    string
	tags    []string
	perm    uint
	config  map[string]interface{}
	bpf     *BpfModule
	fd      int
	subtype string
}

func (adapter *BpfAdapter) Type() string {
	if adapter.subtype != "" {
		return "bpf/" + adapter.subtype
	}
	return "bpf"
}
func (adapter *BpfAdapter) Name() string   { return adapter.name }
func (adapter *BpfAdapter) Tags() []string { return adapter.tags }
func (adapter *BpfAdapter) Perm() uint     { return adapter.perm }

func (adapter *BpfAdapter) SetConfig(req createModuleRequest, g Graph, id int) error {
	var code, fullCode string
	for k, v := range req.Config {
		switch strings.ToLower(k) {
		case "code":
			val, ok := v.(string)
			if !ok {
				return fmt.Errorf("Expected code argument to be a string")
			}
			code = val
			fullCode = strings.Join([]string{iomoduleH, wrapperC, val}, "\n")
		}
	}
	cflags := []string{"-DMODULE_UUID_SHORT=\"" + adapter.uuid[:8] + "\""}

	adapter.name = req.DisplayName
	adapter.tags = req.Tags

	if orig, ok := adapter.config["code"]; ok {
		if orig != code {
			return fmt.Errorf("BPF code update not supported")
		}
	} else {
		adapter.bpf = NewBpfModule(fullCode, cflags)
		if adapter.bpf == nil {
			return fmt.Errorf("Could not load bpf code, check server log for details")
		}
		if err := adapter.Init(); err != nil {
			adapter.Close()
			return err
		}
		adapter.config["code"] = code
	}
	switch {
	case adapter.subtype == "policy":
		for _, node := range g.Nodes() {
			node.(Node).Groups().Remove(id)
		}
		for _, tag := range adapter.tags {
			if node := g.NodeByPath(tag); node != nil {
				node.Groups().Insert(id)
			} else {
				Warn.Printf("Could not find %s for policy\n", tag)
			}
		}
	case adapter.subtype == "forward":
	}
	return nil
}

func (adapter *BpfAdapter) Config() map[string]interface{} { return adapter.config }
func (adapter *BpfAdapter) UUID() string                   { return "m:" + adapter.uuid }
func (adapter *BpfAdapter) FD() int                        { return adapter.fd }

func (adapter *BpfAdapter) Init() error {
	fd, err := adapter.bpf.initRxHandler()
	if err != nil {
		Warn.Printf("Unable to init rx handler: %s\n", err)
		return err
	}
	adapter.fd = fd
	return nil
}

func (adapter *BpfAdapter) Close() {
	if adapter.bpf != nil {
		adapter.bpf.Close()
	}
}

func (adapter *BpfAdapter) Tables() []map[string]interface{} {
	result := [](map[string]interface{}){}
	for table := range adapter.bpf.TableIter() {
		result = append(result, table)
	}
	return result
}

func (adapter *BpfAdapter) Table(name string) AdapterTable {
	id := adapter.bpf.tableId(name)
	if ^uint64(id) == 0 {
		return nil
	}
	return &BpfTable{
		id:     id,
		module: adapter.bpf,
	}
}
