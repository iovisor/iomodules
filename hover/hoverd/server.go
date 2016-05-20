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

// vim: set ts=8:sts=8:sw=8:noet

package hover

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"net/http"
	"runtime"
	"strconv"
	"strings"

	"github.com/gonum/graph"
	"github.com/gonum/graph/traverse"

	"github.com/iovisor/iomodules/hover/adapter"
	"github.com/iovisor/iomodules/hover/api"
)

type routeResponse struct {
	statusCode  int
	contentType string
	body        interface{}
}

type HoverServer struct {
	handler        http.Handler
	adapterEntries AdapterEntries
	patchPanel     *PatchPanel
	g              Graph
	nlmon          *NetlinkMonitor
	renderer       *Renderer
}

type handlerFunc func(r *http.Request) routeResponse

func makeHandler(fn handlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, rq *http.Request) {
		defer func() {
			if r := recover(); r != nil {
				switch err := r.(type) {
				// coming from an internal go library
				case runtime.Error:
					http.Error(w, "Internal error", http.StatusBadRequest)
					panic(err)
				// coming from fmt.Errorf from our own package
				case error:
					Error.Println(err.Error())
					Info.Printf("%s %s %d\n", rq.Method, rq.URL, http.StatusBadRequest)
					http.Error(w, err.Error(), http.StatusBadRequest)
				// coming from a helper library that doesn't use fmt.Errorf()
				case string:
					Error.Println(r)
					Info.Printf("%s %s %d\n", rq.Method, rq.URL, http.StatusBadRequest)
					http.Error(w, "Internal error", http.StatusBadRequest)
				// ??
				default:
					http.Error(w, "Internal error", http.StatusBadRequest)
					panic(r)
				}
			}
		}()

		rsp := fn(rq)
		sendReply(w, rq, &rsp)
		Info.Printf("%s %s %d\n", rq.Method, rq.URL, rsp.statusCode)
		return
	}
}

func redirect(url string, code int) routeResponse {
	return routeResponse{statusCode: code, body: url}
}
func notFound() routeResponse {
	return routeResponse{statusCode: http.StatusNotFound}
}

func sendReply(w http.ResponseWriter, r *http.Request, rsp *routeResponse) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if rsp.body != nil {
		if len(rsp.contentType) != 0 {
			w.Header().Set("Content-Type", rsp.contentType)
		} else {
			w.Header().Set("Content-Type", "application/json")
		}
	}
	switch {
	case rsp.statusCode == 0:
		w.WriteHeader(http.StatusOK)
		rsp.statusCode = http.StatusOK
	case 100 <= rsp.statusCode && rsp.statusCode < 300:
		w.WriteHeader(rsp.statusCode)
	case 300 <= rsp.statusCode && rsp.statusCode < 400:
		loc := ""
		if x, ok := rsp.body.(string); ok {
			loc = x
		}
		http.Redirect(w, r, loc, rsp.statusCode)
	case 400 <= rsp.statusCode:
		if rsp.statusCode == http.StatusNotFound {
			Info.Printf("Not Found: %s\n", r.URL)
			http.NotFound(w, r)
		} else {
			msg := ""
			if x, ok := rsp.body.(string); ok {
				msg = x
			}
			http.Error(w, msg, rsp.statusCode)
		}
	default:
	}
	if rsp.body != nil {
		if err := json.NewEncoder(w).Encode(rsp.body); err != nil {
			panic(err)
		}
	}
}

type AdapterEntries map[string]*adapter.AdapterNode

func (a AdapterEntries) Add(node *adapter.AdapterNode) {
	a[node.adapter.UUID()] = node
}

func (a AdapterEntries) Remove(id string) {
	if node, ok := a[id]; ok {
		if node.adapter.Perm()&PermW == 0 {
			panic(fmt.Errorf("Cannot remove %s, permission denied", id))
		}
		delete(a, id)
	}
}

func (a AdapterEntries) Get(id string) *moduleEntry {
	var result *moduleEntry
	if node, ok := a[id]; ok {
		result = adapterToModuleEntry(node.adapter)
	}
	return result
}

func adapterToModuleEntry(a Adapter) *moduleEntry {
	return &api.Module{
		Id:   a.UUID(),
		Perm: fmt.Sprintf("0%x00", a.Perm()),
		ModuleBase: api.ModuleBase{
			ModuleType:  a.Type(),
			DisplayName: a.Name(),
			Tags:        a.Tags(),
			Config:      a.Config(),
		},
	}
}

func getRequestVar(r *http.Request, key string) string {
	vars := mux.Vars(r)
	if vars == nil {
		panic(fmt.Errorf("Missing parameters in module request"))
	}
	value, ok := vars[key]
	if !ok {
		panic(fmt.Errorf("Missing parameter %s in request", key))
	}
	return value
}

type PatchPanel struct {
	adapter *BpfAdapter
	modules AdapterTable
}

func NewPatchPanel() (pp *PatchPanel, err error) {
	id := NewUUID4()

	pp = &PatchPanel{}
	defer func() {
		if err != nil {
			pp.Close()
			pp = nil
		}
	}()
	pp.adapter = &BpfAdapter{
		uuid:   id,
		name:   "patch",
		config: make(map[string]interface{}),
	}
	code := strings.Join([]string{iomoduleH, patchC}, "\n")
	pp.adapter.bpf = NewBpfModule(code, []string{"-w"})
	if pp.adapter.bpf == nil {
		err = fmt.Errorf("PatchPanel: unable to load core module")
		return
	}
	pp.modules = pp.adapter.Table("modules")
	if pp.modules == nil {
		err = fmt.Errorf("PatchPanel: Unable to load modules table")
		return
	}
	Debug.Printf("Patch panel modules table loaded: %v\n", pp.modules.Config())
	return
}

func (p *PatchPanel) Close() {
	if p.adapter != nil {
		p.adapter.Close()
	}
}

func (s *HoverServer) Init() (err error) {
	s.adapterEntries = make(map[string]*adapter.AdapterNode)
	s.patchPanel, err = NewPatchPanel()
	if err != nil {
		return
	}
	s.renderer = NewRenderer()
	s.nlmon, err = NewNetlinkMonitor(s.g, s.renderer, s.pp.modules)
	if err != nil {
		return
	}
	Info.Printf("NetlinkMonitor=%p\n", s.nlmon)

	return
}

func (s *HoverServer) handleModuleList(r *http.Request) routeResponse {
	entries := []*moduleEntry{}
	for _, node := range s.g.Nodes() {
		switch node := node.(type) {
		case *ExtInterface:
		case *adapter.AdapterNode:
			entries = append(entries, adapterToModuleEntry(node.Adapter()))
		}
	}
	return routeResponse{body: entries}
}

// handleModulePost processes creation of a new Module
func (s *HoverServer) handleModulePost(r *http.Request) routeResponse {
	var req api.Module
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		panic(err)
	}
	id := s.g.NewNodeID()
	stub := NewNodeBase(id, -1, "stub:", strconv.Itoa(id), 1)
	s.g.AddNode(&stub)
	adapter, err := NewAdapter(req, s.g, id)
	if err != nil {
		panic(err)
	}
	node := adapter.NewAdapterNode(adapter)
	s.adapterEntries.Add(node)
	node.SetID(id)
	s.g.RemoveNode(&stub)
	s.g.AddNode(node)
	s.patchPanel.modules.Set(strconv.Itoa(node.ID()), strconv.Itoa(node.FD()))

	s.recomputePolicies()
	entry := adapterToModuleEntry(adapter)
	return routeResponse{body: entry}
}

func (s *HoverServer) handleModuleGet(r *http.Request) routeResponse {
	id := getRequestVar(r, "moduleId")
	node := s.g.NodeByPath(id)
	if node == nil {
		return notFound()
	}
	switch node := node.(type) {
	case *ExtInterface:
	case *adapter.AdapterNode:
		return routeResponse{body: adapterToModuleEntry(node.Adapter())}
	}

	return notFound()
}
func (s *HoverServer) handleModulePut(r *http.Request) routeResponse {
	var req moduleEntry
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		panic(err)
	}
	id := getRequestVar(r, "moduleId")
	node, ok := s.adapterEntries[id]
	if !ok {
		return notFound()
	}

	if err := node.adapter.SetConfig(req.ModuleBase, s.g, node.ID()); err != nil {
		panic(err)
	}

	s.recomputePolicies()
	entry := adapterToModuleEntry(node.adapter)
	return routeResponse{body: entry}
}
func (s *HoverServer) handleModuleDelete(r *http.Request) routeResponse {
	id := getRequestVar(r, "moduleId")
	node, ok := s.adapterEntries[id]
	if !ok {
		return notFound()
	}
	node.adapter.Close()
	delete(s.adapterEntries, id)
	s.g.RemoveNode(node)
	s.recomputePolicies()
	return routeResponse{}
}

func (s *HoverServer) handleModuleTableList(r *http.Request) routeResponse {
	id := getRequestVar(r, "moduleId")
	node, ok := s.adapterEntries[id]
	if !ok {
		return notFound()
	}
	return routeResponse{body: node.adapter.Tables()}
}
func (s *HoverServer) handleModuleTableGet(r *http.Request) routeResponse {
	id := getRequestVar(r, "moduleId")
	node, ok := s.adapterEntries[id]
	if !ok {
		return notFound()
	}
	name := getRequestVar(r, "tableId")
	tbl := node.adapter.Table(name)
	if tbl == nil {
		return notFound()
	}
	return routeResponse{body: tbl.Config()}
}

func (s *HoverServer) handleModuleTableEntryList(r *http.Request) routeResponse {
	id := getRequestVar(r, "moduleId")
	node, ok := s.adapterEntries[id]
	if !ok {
		return notFound()
	}
	name := getRequestVar(r, "tableId")
	tbl := node.adapter.Table(name)
	if tbl == nil {
		return notFound()
	}
	entries := []map[string]interface{}{}
	for entry := range tbl.Iter() {
		entries = append(entries, map[string]interface{}{
			"key":   entry.Key,
			"value": entry.Value,
		})
	}
	return routeResponse{body: entries}
}

type createModuleTableEntryRequest struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func (s *HoverServer) handleModuleTableEntryPost(r *http.Request) routeResponse {
	var req createModuleTableEntryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		panic(err)
	}
	id := getRequestVar(r, "moduleId")
	node, ok := s.adapterEntries[id]
	if !ok {
		return notFound()
	}
	name := getRequestVar(r, "tableId")
	tbl := node.adapter.Table(name)
	if tbl == nil {
		return notFound()
	}
	if err := tbl.Set(req.Key, req.Value); err != nil {
		panic(err)
	}
	return routeResponse{body: map[string]interface{}{
		"key":   req.Key,
		"value": req.Value,
	}}
}
func (s *HoverServer) handleModuleTableEntryGet(r *http.Request) routeResponse {
	id := getRequestVar(r, "moduleId")
	node, ok := s.adapterEntries[id]
	if !ok {
		Warn.Printf("Module %s not found\n", id)
		return notFound()
	}
	name := getRequestVar(r, "tableId")
	tbl := node.adapter.Table(name)
	if tbl == nil {
		Warn.Printf("Module %s table %s not found\n", id, name)
		return notFound()
	}
	entryId := getRequestVar(r, "entryId")
	entry, ok := tbl.Get(entryId)
	if !ok {
		Warn.Printf("Module %s table %s entry %s not found\n", id, name, entryId)
		return notFound()
	}
	return routeResponse{body: entry}
}
func (s *HoverServer) handleModuleTableEntryPut(r *http.Request) routeResponse {
	var req createModuleTableEntryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		panic(err)
	}
	id := getRequestVar(r, "moduleId")
	node, ok := s.adapterEntries[id]
	if !ok {
		return notFound()
	}
	name := getRequestVar(r, "tableId")
	tbl := node.adapter.Table(name)
	if tbl == nil {
		return notFound()
	}
	entryId := getRequestVar(r, "entryId")
	if err := tbl.Set(entryId, req.Value); err != nil {
		panic(err)
	}
	return routeResponse{body: map[string]interface{}{
		"key":   entryId,
		"value": req.Value,
	}}
}
func (s *HoverServer) handleModuleTableEntryDelete(r *http.Request) routeResponse {
	id := getRequestVar(r, "moduleId")
	node, ok := s.adapterEntries[id]
	if !ok {
		return notFound()
	}
	name := getRequestVar(r, "tableId")
	tbl := node.adapter.Table(name)
	if tbl == nil {
		return notFound()
	}
	entryId := getRequestVar(r, "entryId")
	if err := tbl.Delete(entryId); err != nil {
		return notFound()
	}
	return routeResponse{}
}

func (s *HoverServer) lookupNode(nodePath string) Node {
	parts := strings.SplitN(nodePath, ":", 2)
	if len(parts) != 2 {
		panic(fmt.Errorf("Malformed node path %q\n", nodePath))
	}
	switch parts[0] {
	case "i", "external_interfaces":
		node, err := s.nlmon.InterfaceByName(parts[1])
		if err != nil {
			panic(err)
		}
		return node
	case "m", "modules":
		node, ok := s.adapterEntries[nodePath]
		if !ok {
			panic(fmt.Errorf("Module %q not found", nodePath))
		}
		return s.g.Node(node.ID())
	default:
		panic(fmt.Errorf("Unknown node path prefix %q", parts[0]))
	}
	return nil
}

type linkEntry struct {
	Id   string `json:"id"`
	From string `json:"from"`
	To   string `json:"to"`
}

func (s *HoverServer) handleLinkList(r *http.Request) routeResponse {
	edges := []linkEntry{}
	visitFn := func(u, v graph.Node) {
		e := s.g.Edge(u, v).(Edge)
		edges = append(edges, linkEntry{
			Id:   e.ID(),
			From: e.From().(Node).Path(),
			To:   e.To().(Node).Path(),
		})
	}
	t := &traverse.BreadthFirst{Visit: visitFn}
	for _, node := range s.nlmon.Interfaces() {
		t.Walk(s.g, node, nil)
	}
	return routeResponse{body: edges}
}

func (s *HoverServer) handleLinkPost(r *http.Request) routeResponse {
	var req linkEntry
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		panic(err)
	}
	from := s.lookupNode(req.From)
	to := s.lookupNode(req.To)
	if s.g.HasEdgeBetween(from, to) {
		panic(fmt.Errorf("Link already exists between %q and %q", from, to))
	}

	if from.ID() < 0 {
		from.SetID(s.g.NewNodeID())
		s.g.AddNode(from)
	}
	if to.ID() < 0 {
		to.SetID(s.g.NewNodeID())
		s.g.AddNode(to)
	}
	fid, tid := -1, -1
	e1 := NewEdgeChain(from, to, &fid, &tid)
	s.g.SetEdge(e1)
	e2 := NewEdgeChain(to, from, &tid, &fid)
	s.g.SetEdge(e2)

	s.recomputePolicies()
	return routeResponse{body: linkEntry{
		Id:   e1.ID(),
		From: e1.From().(Node).Path(),
		To:   e1.To().(Node).Path(),
	}}
}

func (s *HoverServer) recomputePolicies() {
	nodes := s.nlmon.Interfaces()
	if err := s.renderer.Provision(s.g, nodes); err != nil {
		panic(err)
	}
	DumpDotFile(s.g)
	s.nlmon.EnsureInterfaces(s.g)
	s.renderer.Run(s.g, nodes)
}

func (s *HoverServer) edgeLookup(id string) Edge {
	a, b, err := encrypter.DecodePair(id)
	if err != nil {
		Warn.Printf("edge id decode failed: %s", err)
		return nil
	}
	from, to := s.g.Node(a), s.g.Node(b)
	if from == nil || to == nil {
		return nil
	}

	e := s.g.Edge(from, to)
	if e == nil {
		return nil
	}
	return e.(Edge)
}

func (s *HoverServer) handleLinkGet(r *http.Request) routeResponse {
	id := getRequestVar(r, "linkId")
	e := s.edgeLookup(id)
	if e == nil {
		return notFound()
	}
	return routeResponse{body: linkEntry{
		Id:   e.ID(),
		From: e.From().(Node).Path(),
		To:   e.To().(Node).Path(),
	}}
}
func (s *HoverServer) handleLinkPut(r *http.Request) routeResponse {
	return notFound()
}
func (s *HoverServer) handleLinkDelete(r *http.Request) routeResponse {
	id := getRequestVar(r, "linkId")
	e := s.edgeLookup(id)
	if e == nil {
		return notFound()
	}
	e.MarkDeleted()
	e = s.g.Edge(e.To(), e.From()).(Edge)
	if e != nil {
		// remove also the reverse
		e.MarkDeleted()
	}

	s.recomputePolicies()
	return routeResponse{}
}

type interfaceEntry struct {
	Id   string `json:"id"`
	Name string `json:"name"`
}

func (s *HoverServer) handleExternalInterfaceList(r *http.Request) routeResponse {
	var interfaces []interfaceEntry
	for _, ifc := range s.nlmon.Interfaces() {
		interfaces = append(interfaces, interfaceEntry{
			Id:   fmt.Sprintf("%d", ifc.Link().Attrs().Index),
			Name: ifc.Link().Attrs().Name,
		})
	}
	return routeResponse{
		body: interfaces,
	}
}

func (s *HoverServer) Handler() http.Handler {
	return s.handler
}

func (s *HoverServer) Close() error {
	if s != nil {
		s.patchPanel.Close()
	}
	s.nlmon.Close()
	return nil
}

func NewServer() *HoverServer {
	Info.Println("IOVisor HTTP Daemon starting...")
	rtr := mux.NewRouter()

	s := &HoverServer{
		handler: rtr,
		g:       NewGraph(),
	}
	err := s.Init()
	if err != nil {
		return nil
	}

	// modules
	// modules/{moduleId}/tables
	// modules/{moduleId}/tables/{tableId}/entries
	// links
	// external_interfaces

	mod := rtr.PathPrefix("/modules").Subrouter()
	mod.Methods("GET").Path("/").HandlerFunc(makeHandler(s.handleModuleList))
	mod.Methods("POST").Path("/").HandlerFunc(makeHandler(s.handleModulePost))
	mod.Methods("GET").Path("/{moduleId}").HandlerFunc(makeHandler(s.handleModuleGet))
	mod.Methods("PUT").Path("/{moduleId}").HandlerFunc(makeHandler(s.handleModulePut))
	mod.Methods("DELETE").Path("/{moduleId}").HandlerFunc(makeHandler(s.handleModuleDelete))

	tbl := mod.PathPrefix("/{moduleId}/tables").Subrouter()
	tbl.Methods("GET").Path("/").HandlerFunc(makeHandler(s.handleModuleTableList))
	tbl.Methods("GET").Path("/{tableId}").HandlerFunc(makeHandler(s.handleModuleTableGet))

	ent := tbl.PathPrefix("/{tableId}/entries").Subrouter()
	ent.Methods("GET").Path("/").HandlerFunc(makeHandler(s.handleModuleTableEntryList))
	ent.Methods("POST").Path("/").HandlerFunc(makeHandler(s.handleModuleTableEntryPost))
	ent.Methods("GET").Path("/{entryId}").HandlerFunc(makeHandler(s.handleModuleTableEntryGet))
	ent.Methods("PUT").Path("/{entryId}").HandlerFunc(makeHandler(s.handleModuleTableEntryPut))
	ent.Methods("DELETE").Path("/{entryId}").HandlerFunc(makeHandler(s.handleModuleTableEntryDelete))

	lnk := rtr.PathPrefix("/links").Subrouter()
	lnk.Methods("GET").Path("/").HandlerFunc(makeHandler(s.handleLinkList))
	lnk.Methods("POST").Path("/").HandlerFunc(makeHandler(s.handleLinkPost))
	lnk.Methods("GET").Path("/{linkId}").HandlerFunc(makeHandler(s.handleLinkGet))
	lnk.Methods("PUT").Path("/{linkId}").HandlerFunc(makeHandler(s.handleLinkPut))
	lnk.Methods("DELETE").Path("/{linkId}").HandlerFunc(makeHandler(s.handleLinkDelete))

	ext := rtr.PathPrefix("/external_interfaces").Subrouter()
	ext.Methods("GET").Path("/").HandlerFunc(makeHandler(s.handleExternalInterfaceList))

	return s
}
