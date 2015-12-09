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

package hive

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"strings"
	"unsafe"
)

/*
#cgo LDFLAGS: -lbcc
#include <bcc/bpf_common.h>
#include <bcc/libbpf.h>
*/
import "C"

// BpfModule type
type BpfModule struct {
	p     unsafe.Pointer
	funcs map[string]int
}

var (
	cHeader string
)

func init() {
	b, err := ioutil.ReadFile(".wrapper.c")
	if err != nil {
		panic(err)
	}
	cHeader = string(b)
}

// NewBpfModule constructor
func NewBpfModule(code string) *BpfModule {
	Debug.Println("Creating BpfModule from string")
	cs := C.CString(code)
	defer C.free(unsafe.Pointer(cs))
	c := C.bpf_module_create_c_from_string(cs, 0)
	if c == nil {
		return nil
	}
	return &BpfModule{
		p:     c,
		funcs: make(map[string]int),
	}
}
func (bpf *BpfModule) Close() {
	Debug.Println("Closing BpfModule")
	C.bpf_module_destroy(bpf.p)
}

func (bpf *BpfModule) initRxHandler() (int, error) {
	fd, err := bpf.Load("handle_rx_wrapper", C.BPF_PROG_TYPE_SCHED_ACT)
	if err != nil {
		return -1, err
	}
	return fd, nil
}

func (bpf *BpfModule) Load(name string, progType int) (int, error) {
	fd, ok := bpf.funcs[name]
	if ok {
		return fd, nil
	}
	fd, err := bpf.load(name, progType)
	if err != nil {
		return -1, err
	}
	bpf.funcs[name] = fd
	return fd, nil
}

func (bpf *BpfModule) load(name string, progType int) (int, error) {
	nameCS := C.CString(name)
	defer C.free(unsafe.Pointer(nameCS))
	start := (*C.struct_bpf_insn)(C.bpf_function_start(bpf.p, nameCS))
	size := C.int(C.bpf_function_size(bpf.p, nameCS))
	license := C.bpf_module_license(bpf.p)
	version := C.bpf_module_kern_version(bpf.p)
	if start == nil {
		return -1, fmt.Errorf("BpfModule: unable to find handle_rx_wrapper")
	}
	logbuf := make([]byte, 65536)
	logbufP := (*C.char)(unsafe.Pointer(&logbuf[0]))
	fd := C.bpf_prog_load(uint32(progType), start, size, license, version, logbufP, C.uint(len(logbuf)))
	if fd < 0 {
		msg := string(logbuf[:bytes.IndexByte(logbuf, 0)])
		return -1, fmt.Errorf("Error loading bpf program:\n%s", msg)
	}
	return int(fd), nil
}

func (bpf *BpfModule) TableSize() uint64 {
	size := C.bpf_num_tables(bpf.p)
	return uint64(size)
}

func (bpf *BpfModule) tableId(name string) C.size_t {
	cs := C.CString(name)
	defer C.free(unsafe.Pointer(cs))
	return C.bpf_table_id(bpf.p, cs)
}

func (bpf *BpfModule) TableDesc(id uint64) map[string]interface{} {
	i := C.size_t(id)
	return map[string]interface{}{
		"name":      C.GoString(C.bpf_table_name(bpf.p, i)),
		"fd":        int(C.bpf_table_fd_id(bpf.p, i)),
		"key_size":  uint64(C.bpf_table_key_size_id(bpf.p, i)),
		"leaf_size": uint64(C.bpf_table_leaf_size_id(bpf.p, i)),
		"key_desc":  C.GoString(C.bpf_table_key_desc_id(bpf.p, i)),
		"leaf_desc": C.GoString(C.bpf_table_leaf_desc_id(bpf.p, i)),
	}
}

func (bpf *BpfModule) TableIter() <-chan map[string]interface{} {
	ch := make(chan map[string]interface{})
	go func() {
		size := C.bpf_num_tables(bpf.p)
		for i := C.size_t(0); i < size; i++ {
			ch <- bpf.TableDesc(uint64(i))
		}
		close(ch)
	}()
	return ch
}

type BpfAdapter struct {
	id         string
	handle     uint
	name       string
	perm       uint
	config     map[string]interface{}
	bpf        *BpfModule
	patchPanel *PatchPanel
	interfaces *HandlePool
}

func (adapter *BpfAdapter) Type() string {
	return "bpf"
}

func (adapter *BpfAdapter) Name() string {
	return adapter.name
}

func (adapter *BpfAdapter) Perm() uint {
	return adapter.perm
}

func (adapter *BpfAdapter) SetConfig(config map[string]interface{}) error {
	for k, v := range config {
		switch strings.ToLower(k) {
		case "code":
			val, ok := v.(string)
			if !ok {
				return fmt.Errorf("Expected code argument to be a string")
			}
			adapter.bpf = NewBpfModule(fmt.Sprintf("%s\n%s", cHeader, val))
			if adapter.bpf == nil {
				return fmt.Errorf("Could not load bpf code, check server log for details")
			}
			if err := adapter.Init(); err != nil {
				adapter.Close()
				return err
			}
			adapter.config["code"] = val
		}
	}
	return nil
}

func (adapter *BpfAdapter) Config() map[string]interface{} {
	return adapter.config
}

func (adapter *BpfAdapter) ID() string {
	return adapter.id
}
func (adapter *BpfAdapter) Handle() uint {
	return adapter.handle
}

func (adapter *BpfAdapter) Init() error {
	fd, err := adapter.bpf.initRxHandler()
	if err != nil {
		return err
	}
	return adapter.patchPanel.Register(adapter, fd)
}

func (adapter *BpfAdapter) Close() {
	if adapter.bpf != nil {
		adapter.bpf.Close()
	}
	adapter.patchPanel.Unregister(adapter)
}

func (adapter *BpfAdapter) CreateInterface() (uint, error) {
	handle, err := adapter.interfaces.Acquire()
	if err != nil {
		return 0, err
	}
	return handle, nil
}

func (adapter *BpfAdapter) DeleteInterface(id uint) error {
	adapter.interfaces.Release(id)
	return nil
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
	if id == ^C.size_t(0) {
		return nil
	}
	return &BpfTable{
		id:     id,
		module: adapter.bpf,
	}
}

type BpfTable struct {
	id     C.size_t
	module *BpfModule
}

func (table *BpfTable) ID() string {
	return C.GoString(C.bpf_table_name(table.module.p, table.id))
}
func (table *BpfTable) Name() string {
	return C.GoString(C.bpf_table_name(table.module.p, table.id))
}
func (table *BpfTable) Config() map[string]interface{} {
	mod := table.module.p
	return map[string]interface{}{
		"name":      C.GoString(C.bpf_table_name(mod, table.id)),
		"fd":        int(C.bpf_table_fd_id(mod, table.id)),
		"key_size":  uint64(C.bpf_table_key_size_id(mod, table.id)),
		"leaf_size": uint64(C.bpf_table_leaf_size_id(mod, table.id)),
		"key_desc":  C.GoString(C.bpf_table_key_desc_id(mod, table.id)),
		"leaf_desc": C.GoString(C.bpf_table_leaf_desc_id(mod, table.id)),
	}
}
func (table *BpfTable) keyToString(key []byte) string {
	key_size := C.bpf_table_key_size_id(table.module.p, table.id)
	keyP := unsafe.Pointer(&key[0])
	keyStr := make([]byte, key_size*8)
	keyStrP := (*C.char)(unsafe.Pointer(&keyStr[0]))
	r := C.bpf_table_key_snprintf(table.module.p, table.id, keyStrP, C.size_t(len(keyStr)), keyP)
	if r == 0 {
		return string(keyStr)
	}
	return ""
}
func (table *BpfTable) leafToString(leaf []byte) string {
	leaf_size := C.bpf_table_leaf_size_id(table.module.p, table.id)
	leafP := unsafe.Pointer(&leaf[0])
	leafStr := make([]byte, leaf_size*8)
	leafStrP := (*C.char)(unsafe.Pointer(&leafStr[0]))
	r := C.bpf_table_leaf_snprintf(table.module.p, table.id, leafStrP, C.size_t(len(leafStr)), leafP)
	if r == 0 {
		return string(leafStr)
	}
	return ""
}

func (table *BpfTable) keyToBytes(keyX interface{}) ([]byte, error) {
	mod := table.module.p
	key_size := C.bpf_table_key_size_id(mod, table.id)
	keyStr, ok := keyX.(string)
	if !ok {
		return nil, fmt.Errorf("table key must be a string")
	}
	key := make([]byte, key_size)
	keyP := unsafe.Pointer(&key[0])
	keyCS := C.CString(keyStr)
	defer C.free(unsafe.Pointer(keyCS))
	r := C.bpf_table_key_sscanf(mod, table.id, keyCS, keyP)
	if r != 0 {
		return nil, fmt.Errorf("error scanning key from string")
	}
	return key, nil
}

func (table *BpfTable) leafToBytes(leafX interface{}) ([]byte, error) {
	mod := table.module.p
	leaf_size := C.bpf_table_leaf_size_id(mod, table.id)
	leafStr, ok := leafX.(string)
	if !ok {
		return nil, fmt.Errorf("table leaf must be a string")
	}
	leaf := make([]byte, leaf_size)
	leafP := unsafe.Pointer(&leaf[0])
	leafCS := C.CString(leafStr)
	defer C.free(unsafe.Pointer(leafCS))
	r := C.bpf_table_leaf_sscanf(mod, table.id, leafCS, leafP)
	if r != 0 {
		return nil, fmt.Errorf("error scanning leaf from string")
	}
	return leaf, nil
}

// Get takes a key and returns the value or nil, and an 'ok' style indicator
func (table *BpfTable) Get(keyX interface{}) (interface{}, bool) {
	mod := table.module.p
	fd := C.bpf_table_fd_id(mod, table.id)
	leaf_size := C.bpf_table_leaf_size_id(mod, table.id)
	key, err := table.keyToBytes(keyX)
	if err != nil {
		return nil, false
	}
	leaf := make([]byte, leaf_size)
	keyP := unsafe.Pointer(&key[0])
	leafP := unsafe.Pointer(&leaf[0])
	r := C.bpf_lookup_elem(fd, keyP, leafP)
	if r != 0 {
		return nil, false
	}
	leafStr := make([]byte, leaf_size*8)
	leafStrP := (*C.char)(unsafe.Pointer(&leafStr[0]))
	r = C.bpf_table_leaf_snprintf(mod, table.id, leafStrP, C.size_t(len(leafStr)), leafP)
	if r != 0 {
		return nil, false
	}
	return AdapterTablePair{
		Key:   keyX,
		Value: string(leafStr[:bytes.IndexByte(leafStr, 0)]),
	}, true
	return nil, false
}

func (table *BpfTable) Set(keyX, leafX interface{}) error {
	fd := C.bpf_table_fd_id(table.module.p, table.id)
	key, err := table.keyToBytes(keyX)
	if err != nil {
		return err
	}
	leaf, err := table.leafToBytes(leafX)
	if err != nil {
		return err
	}
	keyP := unsafe.Pointer(&key[0])
	leafP := unsafe.Pointer(&leaf[0])
	r := C.bpf_update_elem(fd, keyP, leafP, 0)
	if r != 0 {
		return fmt.Errorf("BpfTable.Set: unable to update element")
	}
	return nil
}
func (table *BpfTable) Delete(keyX interface{}) error {
	fd := C.bpf_table_fd_id(table.module.p, table.id)
	key, err := table.keyToBytes(keyX)
	if err != nil {
		return err
	}
	keyP := unsafe.Pointer(&key[0])
	r := C.bpf_delete_elem(fd, keyP)
	if r != 0 {
		return fmt.Errorf("BpfTable.Delete: unable to delete element")
	}
	return nil
}
func (table *BpfTable) Iter() <-chan AdapterTablePair {
	mod := table.module.p
	ch := make(chan AdapterTablePair, 128)
	go func() {
		defer close(ch)
		fd := C.bpf_table_fd_id(mod, table.id)
		key_size := C.bpf_table_key_size_id(mod, table.id)
		leaf_size := C.bpf_table_leaf_size_id(mod, table.id)
		key := make([]byte, key_size)
		leaf := make([]byte, leaf_size)
		keyP := unsafe.Pointer(&key[0])
		leafP := unsafe.Pointer(&leaf[0])
		alternateKeys := []byte{0xff, 0x55}
		res := C.bpf_lookup_elem(fd, keyP, leafP)
		// make sure the start iterator is an invalid key
		for i := 0; i <= len(alternateKeys); i++ {
			if res < 0 {
				break
			}
			for j := range key {
				key[j] = alternateKeys[i]
			}
			res = C.bpf_lookup_elem(fd, keyP, leafP)
		}
		if res == 0 {
			Info.Println("BpfTable.Iter: No valid initial key found")
			return
		}
		keyStr := make([]byte, key_size*8)
		leafStr := make([]byte, leaf_size*8)
		keyStrP := (*C.char)(unsafe.Pointer(&keyStr[0]))
		leafStrP := (*C.char)(unsafe.Pointer(&leafStr[0]))
		for res = C.bpf_get_next_key(fd, keyP, keyP); res == 0; res = C.bpf_get_next_key(fd, keyP, keyP) {
			r := C.bpf_lookup_elem(fd, keyP, leafP)
			if r != 0 {
				continue
			}
			r = C.bpf_table_key_snprintf(mod, table.id, keyStrP, C.size_t(len(keyStr)), keyP)
			if r != 0 {
				break
			}
			r = C.bpf_table_leaf_snprintf(mod, table.id, leafStrP, C.size_t(len(leafStr)), leafP)
			if r != 0 {
				break
			}
			ch <- AdapterTablePair{
				Key:   string(keyStr[:bytes.IndexByte(keyStr, 0)]),
				Value: string(leafStr[:bytes.IndexByte(leafStr, 0)]),
			}
		}
	}()
	return ch
}
