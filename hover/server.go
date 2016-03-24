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
	"strings"

	"github.com/gonum/graph"
	"github.com/gonum/graph/traverse"
	"golang.org/x/tools/container/intsets"
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
	hmon           *HostMonitor
	renderer       *Renderer
}

type handlerFunc func(r *http.Request) routeResponse

func makeHandler(fn handlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
					http.Error(w, err.Error(), http.StatusBadRequest)
				// coming from a helper library that doesn't use fmt.Errorf()
				case string:
					Error.Println(r)
					http.Error(w, "Internal error", http.StatusBadRequest)
				// ??
				default:
					http.Error(w, "Internal error", http.StatusBadRequest)
					panic(r)
				}
			}
		}()

		rsp := fn(r)
		sendReply(w, r, &rsp)
		Info.Printf("%s %s %d\n", r.Method, r.URL, rsp.statusCode)
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

type createModuleRequest struct {
	ModuleType  string                 `json:"module_type"`
	DisplayName string                 `json:"display_name"`
	Tags        []string               `json:"tags"`
	Config      map[string]interface{} `json:"config"`
}
type moduleEntry struct {
	createModuleRequest
	Id   string `json:"id"`
	Perm string `json:"permissions"`
}

type AdapterEntries map[string]*AdapterNode

func (a AdapterEntries) Add(node *AdapterNode) {
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

func (a AdapterEntries) GetAll() []*moduleEntry {
	result := []*moduleEntry{}
	for _, node := range a {
		result = append(result, &moduleEntry{
			createModuleRequest: createModuleRequest{
				ModuleType:  node.adapter.Type(),
				DisplayName: node.adapter.Name(),
				Tags:        node.adapter.Tags(),
				Config:      node.adapter.Config(),
			},
			Id:   node.adapter.UUID(),
			Perm: fmt.Sprintf("0%x00", node.adapter.Perm()),
		})
	}
	return result
}

func (a AdapterEntries) Get(id string) *moduleEntry {
	var result *moduleEntry
	if node, ok := a[id]; ok {
		result = adapterToModuleEntry(node.adapter)
	}
	return result
}

func adapterToModuleEntry(a Adapter) *moduleEntry {
	return &moduleEntry{
		Id:   a.UUID(),
		Perm: fmt.Sprintf("0%x00", a.Perm()),
		createModuleRequest: createModuleRequest{
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
		panic(fmt.Errorf("Missing parameter moduleId in request"))
	}
	return value
}

func (s *HoverServer) Init() (err error) {
	s.adapterEntries = make(map[string]*AdapterNode)
	s.patchPanel, err = NewPatchPanel()
	if err != nil {
		return
	}
	s.hmon, err = NewHostMonitor(s.g)
	if err != nil {
		return
	}
	s.renderer = NewRenderer()

	return
}

func (s *HoverServer) handleModuleList(r *http.Request) routeResponse {
	entries := s.adapterEntries.GetAll()
	return routeResponse{body: entries}
}

// handleModulePost processes creation of a new Module
func (s *HoverServer) handleModulePost(r *http.Request) routeResponse {
	var req createModuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		panic(err)
	}
	id := s.g.NewNodeID()
	adapter, err := NewAdapter(req, s.g, id)
	if err != nil {
		panic(err)
	}
	node := NewAdapterNode(adapter)
	s.adapterEntries.Add(node)
	node.SetID(id)
	s.g.AddNode(node)
	entry := adapterToModuleEntry(adapter)
	return routeResponse{body: entry}
}

func (s *HoverServer) handleModuleGet(r *http.Request) routeResponse {
	id := getRequestVar(r, "moduleId")
	entry := s.adapterEntries.Get(id)
	if entry == nil {
		return notFound()
	}
	return routeResponse{body: entry}
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

	if err := node.adapter.SetConfig(req.createModuleRequest, s.g, node.ID()); err != nil {
		panic(err)
	}

	return routeResponse{}
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
	parts := strings.SplitN(nodePath, "/", 2)
	if len(parts) != 2 {
		panic(fmt.Errorf("Malformed node path %q\n", nodePath))
	}
	switch parts[0] {
	case "i", "external_interfaces":
		node, err := s.hmon.InterfaceByName(parts[1])
		if err != nil {
			panic(err)
		}
		return node
	case "m", "modules":
		node, ok := s.adapterEntries[parts[1]]
		if !ok {
			panic(fmt.Errorf("Module %q not found", parts[1]))
		}
		return s.g.Node(node.ID())
	default:
		panic(fmt.Errorf("Unknown node path prefix %q", parts[0]))
	}
	return nil
}

type linkEntry struct {
	From string `json:"from"`
	To   string `json:"to"`
}

func (s *HoverServer) handleLinkList(r *http.Request) routeResponse {
	var edges []linkEntry
	visitFn := func(u, v graph.Node) {
		e := s.g.Edge(u, v).(Edge)
		edges = append(edges, linkEntry{e.From().(Node).Path(), e.To().(Node).Path()})
	}
	t := &traverse.BreadthFirst{Visit: visitFn}
	for _, node := range s.hmon.Interfaces() {
		t.Walk(s.g, node, nil)
	}
	return routeResponse{body: edges}
}

func computeChain(from, to Node) (fromto []int, tofrom []int, err error) {
	// For a new link, there is a chain in each direction to be computed and downloaded.
	// Every link is specified as from:to, but we also implicitly create to:from.
	//
	// To compute the chain in each direction, the following algorithm is followed:
	//  Let T and F represent the set of groups for the 'to' and 'from' nodes, respectively.
	//  The leaving set L is the set difference between F and T.
	//  L := F - T
	//  The entering set E is the set difference between T and F
	//  E := T - F
	//
	// For the link from:to, the chain is built as follows:
	//  For each module e in E, invoke the ingress policy (e.ifc[1])
	//  For each module l in L, invoke the egress policy (l.ifc[2])
	// For the link to:from, the chain is build as follows (reversed of above):
	//  For each module l in L, invoke the ingress policy (l.ifc[1])
	//  For each module e in E, invoke the egress policy (e.ifc[2])

	var e, l intsets.Sparse
	l.Difference(from.Groups(), to.Groups())
	e.Difference(to.Groups(), from.Groups())

	if (e.Len() + l.Len()) > 2 {
		err = fmt.Errorf("Too many policies between %s and %s", from, to)
		return
	}

	var x intsets.Sparse
	var id int

	x.Copy(&e)
	for x.TakeMin(&id) {
		fromto = append(fromto, 1<<16|id)
	}
	x.Copy(&l)
	for x.TakeMin(&id) {
		fromto = append(fromto, 2<<16|id)
	}

	x.Copy(&l)
	for x.TakeMin(&id) {
		tofrom = append(tofrom, 1<<16|id)
	}
	x.Copy(&e)
	for x.TakeMin(&id) {
		tofrom = append(tofrom, 2<<16|id)
	}
	return
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

	fromto, tofrom, err := computeChain(from, to)
	if err != nil {
		panic(err)
	}

	fromID, err := from.NewInterfaceID()
	if err != nil {
		panic(err)
	}

	toID, err := to.NewInterfaceID()
	if err != nil {
		from.ReleaseInterfaceID(fromID)
		panic(err)
	}

	if from.ID() < 0 {
		from.SetID(s.g.NewNodeID())
		s.g.AddNode(from)
	}
	if to.ID() < 0 {
		to.SetID(s.g.NewNodeID())
		s.g.AddNode(to)
	}

	fromto = append(fromto, toID<<16|to.ID())
	tofrom = append(tofrom, fromID<<16|from.ID())
	var fromto2, tofrom2 [3]int
	for i, x := range fromto {
		fromto2[i] = x
	}
	for i, x := range tofrom {
		tofrom2[i] = x
	}
	Info.Printf("fromto(%d.%d):%x, tofrom(%d.%d):%x\n", from.ID(), fromID, fromto2, to.ID(), toID, tofrom2)
	s.g.SetEdge(EdgeChain{from, to, fromto2, fromID, toID})
	s.g.SetEdge(EdgeChain{to, from, tofrom2, toID, fromID})
	s.recomputePolicies()
	return routeResponse{}
}

func (s *HoverServer) recomputePolicies() {
	s.hmon.EnsureInterfaces(s.g, s.patchPanel)
	s.renderer.Run(s.g, s.patchPanel, s.hmon)
	DumpDotFile(s.g)
}
func (s *HoverServer) handleLinkGet(r *http.Request) routeResponse {
	return routeResponse{}
}
func (s *HoverServer) handleLinkPut(r *http.Request) routeResponse {
	return notFound()
}
func (s *HoverServer) handleLinkDelete(r *http.Request) routeResponse {
	return routeResponse{}
}

type interfaceEntry struct {
	Id   string `json:"id"`
	Name string `json:"name"`
}

func (s *HoverServer) handleModuleInterfaceList(r *http.Request) routeResponse {
	id := getRequestVar(r, "moduleId")
	node, ok := s.adapterEntries[id]
	if !ok {
		return notFound()
	}
	interfaces := []*interfaceEntry{}
	for ifc := range node.adapter.Interfaces() {
		interfaces = append(interfaces, &interfaceEntry{
			Id:   fmt.Sprintf("%d", ifc.ID()),
			Name: ifc.Name(),
		})
	}
	return routeResponse{body: interfaces}
}
func (s *HoverServer) handleModuleInterfaceGet(r *http.Request) routeResponse {
	id := getRequestVar(r, "moduleId")
	node, ok := s.adapterEntries[id]
	if !ok {
		return notFound()
	}
	ifcId := getRequestVar(r, "interfaceId")
	ifc := node.adapter.InterfaceByName(ifcId)
	if ifc == nil {
		return notFound()
	}
	return routeResponse{body: &interfaceEntry{
		Id:   fmt.Sprintf("%d", ifc.ID()),
		Name: ifc.Name(),
	}}
}

func (s *HoverServer) handleExternalInterfaceList(r *http.Request) routeResponse {
	var interfaces []interfaceEntry
	for _, ifc := range s.hmon.Interfaces() {
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

	ifc := mod.PathPrefix("/{moduleId}/interfaces").Subrouter()
	ifc.Methods("GET").Path("/").HandlerFunc(makeHandler(s.handleModuleInterfaceList))
	ifc.Methods("GET").Path("/{interfaceId}").HandlerFunc(makeHandler(s.handleModuleInterfaceGet))

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
	lnk.Methods("GET").Path("/{connId}").HandlerFunc(makeHandler(s.handleLinkGet))
	lnk.Methods("PUT").Path("/{connId}").HandlerFunc(makeHandler(s.handleLinkPut))
	lnk.Methods("DELETE").Path("/{connId}").HandlerFunc(makeHandler(s.handleLinkDelete))

	ext := rtr.PathPrefix("/external_interfaces").Subrouter()
	ext.Methods("GET").Path("/").HandlerFunc(makeHandler(s.handleExternalInterfaceList))

	return s
}
