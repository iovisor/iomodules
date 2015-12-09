// vim: set ts=8:sts=8:sw=8:noet

package hive

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"net/http"
	"runtime"
	"sync"
)

type routeResponse struct {
	statusCode  int
	contentType string
	body        interface{}
}

type handlerFunc func(r *http.Request) routeResponse

func makeHandler(fn handlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		Info.Printf("%s %s\n", r.Method, r.URL)
		defer func() {
			if r := recover(); r != nil {
				switch err := r.(type) {
				case runtime.Error:
					http.Error(w, "Internal error", http.StatusBadRequest)
					panic(err)
				case error:
					Error.Println(err.Error())
					http.Error(w, err.Error(), http.StatusBadRequest)
				default:
					http.Error(w, "Internal error", http.StatusBadRequest)
					panic(r)
				}
			}
		}()

		rsp := fn(r)
		sendReply(w, r, rsp)
		return
	}
}

func redirect(url string, code int) routeResponse {
	return routeResponse{statusCode: code, body: url}
}
func notFound() routeResponse {
	return routeResponse{statusCode: http.StatusNotFound}
}

func sendReply(w http.ResponseWriter, r *http.Request, rsp routeResponse) {
	if rsp.body != nil {
		if len(rsp.contentType) != 0 {
			w.Header().Set("Content-Type", rsp.contentType)
		} else {
			w.Header().Set("Content-Type", "application/json")
		}
	}
	switch {
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
	Config      map[string]interface{} `json:"config"`
}
type moduleEntry struct {
	Id          string                 `json:"id"`
	ModuleType  string                 `json:"module_type"`
	DisplayName string                 `json:"display_name"`
	Config      map[string]interface{} `json:"config"`
}

type AdapterEntries struct {
	mtx        sync.RWMutex
	m          map[string]Adapter
	patchPanel *PatchPanel
}

var (
	adapterEntries AdapterEntries
)

func init() {
	adapterEntries.m = make(map[string]Adapter)
	var err error
	adapterEntries.patchPanel, err = NewPatchPanel()
	if err != nil {
		panic(err)
	}
}

func (a *AdapterEntries) Add(adapter Adapter) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	a.m[adapter.ID()] = adapter
}

func (a *AdapterEntries) Remove(id string) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	delete(a.m, id)
}

func (a *AdapterEntries) GetAll() []*moduleEntry {
	a.mtx.RLock()
	defer a.mtx.RUnlock()
	result := []*moduleEntry{}
	for _, adapter := range a.m {
		result = append(result, &moduleEntry{
			Id:          adapter.ID(),
			ModuleType:  adapter.Type(),
			DisplayName: adapter.Name(),
			Config:      adapter.Config(),
		})
	}
	return result
}

func (a *AdapterEntries) Get(id string) *moduleEntry {
	a.mtx.RLock()
	defer a.mtx.RUnlock()
	var result *moduleEntry
	if adapter, ok := a.m[id]; ok {
		result = adapterToModuleEntry(adapter)
	}
	return result
}

func adapterToModuleEntry(a Adapter) *moduleEntry {
	return &moduleEntry{
		Id:          a.ID(),
		ModuleType:  a.Type(),
		DisplayName: a.Name(),
		Config:      a.Config(),
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

func handleModuleList(r *http.Request) routeResponse {
	entries := adapterEntries.GetAll()
	return routeResponse{body: entries}
}

// handleModulePost processes creation of a new Module
func handleModulePost(r *http.Request) routeResponse {
	var req createModuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		panic(err)
	}
	adapter, err := NewAdapter(&req, adapterEntries.patchPanel)
	if err != nil {
		panic(err)
	}
	adapterEntries.Add(adapter)
	entry := adapterToModuleEntry(adapter)
	return routeResponse{body: entry}
}

func handleModuleGet(r *http.Request) routeResponse {
	id := getRequestVar(r, "moduleId")
	entry := adapterEntries.Get(id)
	if entry == nil {
		return notFound()
	}
	return routeResponse{body: entry}
}
func handleModulePut(r *http.Request) routeResponse {
	return routeResponse{}
}
func handleModuleDelete(r *http.Request) routeResponse {
	id := getRequestVar(r, "moduleId")
	adapterEntries.mtx.Lock()
	defer adapterEntries.mtx.Unlock()
	adapter, ok := adapterEntries.m[id]
	if !ok {
		return notFound()
	}
	adapter.Close()
	delete(adapterEntries.m, id)
	return routeResponse{}
}

func handleModuleTableList(r *http.Request) routeResponse {
	id := getRequestVar(r, "moduleId")
	adapterEntries.mtx.RLock()
	defer adapterEntries.mtx.RUnlock()
	adapter, ok := adapterEntries.m[id]
	if !ok {
		return notFound()
	}
	return routeResponse{body: adapter.Tables()}
}
func handleModuleTableGet(r *http.Request) routeResponse {
	id := getRequestVar(r, "moduleId")
	adapterEntries.mtx.RLock()
	defer adapterEntries.mtx.RUnlock()
	adapter, ok := adapterEntries.m[id]
	if !ok {
		return notFound()
	}
	name := getRequestVar(r, "tableId")
	tbl := adapter.Table(name)
	if tbl == nil {
		return notFound()
	}
	return routeResponse{body: tbl.Config()}
}

func handleModuleTableEntryList(r *http.Request) routeResponse {
	id := getRequestVar(r, "moduleId")
	adapterEntries.mtx.RLock()
	defer adapterEntries.mtx.RUnlock()
	adapter, ok := adapterEntries.m[id]
	if !ok {
		return notFound()
	}
	name := getRequestVar(r, "tableId")
	tbl := adapter.Table(name)
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

func handleModuleTableEntryPost(r *http.Request) routeResponse {
	var req createModuleTableEntryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		panic(err)
	}
	id := getRequestVar(r, "moduleId")
	adapterEntries.mtx.RLock()
	defer adapterEntries.mtx.RUnlock()
	adapter, ok := adapterEntries.m[id]
	if !ok {
		return notFound()
	}
	name := getRequestVar(r, "tableId")
	tbl := adapter.Table(name)
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
func handleModuleTableEntryGet(r *http.Request) routeResponse {
	id := getRequestVar(r, "moduleId")
	adapterEntries.mtx.RLock()
	defer adapterEntries.mtx.RUnlock()
	adapter, ok := adapterEntries.m[id]
	if !ok {
		return notFound()
	}
	name := getRequestVar(r, "tableId")
	tbl := adapter.Table(name)
	if tbl == nil {
		return notFound()
	}
	entryId := getRequestVar(r, "entryId")
	entry, ok := tbl.Get(entryId)
	if !ok {
		return notFound()
	}
	return routeResponse{body: entry}
}
func handleModuleTableEntryPut(r *http.Request) routeResponse {
	var req createModuleTableEntryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		panic(err)
	}
	id := getRequestVar(r, "moduleId")
	adapterEntries.mtx.RLock()
	defer adapterEntries.mtx.RUnlock()
	adapter, ok := adapterEntries.m[id]
	if !ok {
		return notFound()
	}
	name := getRequestVar(r, "tableId")
	tbl := adapter.Table(name)
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
func handleModuleTableEntryDelete(r *http.Request) routeResponse {
	id := getRequestVar(r, "moduleId")
	adapterEntries.mtx.RLock()
	defer adapterEntries.mtx.RUnlock()
	adapter, ok := adapterEntries.m[id]
	if !ok {
		return notFound()
	}
	name := getRequestVar(r, "tableId")
	tbl := adapter.Table(name)
	if tbl == nil {
		return notFound()
	}
	entryId := getRequestVar(r, "entryId")
	if err := tbl.Delete(entryId); err != nil {
		return notFound()
	}
	return routeResponse{}
}

type linkEntry struct {
	Id      string   `json:"id"`
	Modules []string `json:"modules"`
}

func handleLinkList(r *http.Request) routeResponse {
	entries := []*linkEntry{}
	return routeResponse{body: entries}
}

type createLinkRequest struct {
	Modules []string `json:"modules"`
}

func handleLinkPost(r *http.Request) routeResponse {
	var req createLinkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		panic(err)
	}
	if len(req.Modules) < 2 {
		panic(fmt.Errorf("Too few modules in connect request"))
	}
	var adapters []Adapter
	for _, id := range req.Modules {
		a, ok := adapterEntries.m[id]
		if !ok {
			panic(fmt.Errorf("Reference to module %s not found in connect request", id))
		}
		adapters = append(adapters, a)
	}
	id, err := adapterEntries.patchPanel.Connect(adapters[0], adapters[1])
	if err != nil {
		panic(err)
	}
	return routeResponse{
		body: &linkEntry{
			Id:      id,
			Modules: req.Modules,
		},
	}
}
func handleLinkGet(r *http.Request) routeResponse {
	return routeResponse{}
}
func handleLinkPut(r *http.Request) routeResponse {
	return routeResponse{}
}
func handleLinkDelete(r *http.Request) routeResponse {
	return routeResponse{}
}

func handleModuleInterfaceList(r *http.Request) routeResponse {
	return routeResponse{}
}
func handleModuleInterfaceGet(r *http.Request) routeResponse {
	return routeResponse{}
}

func NewServer() http.Handler {
	Info.Println("IOVisor HTTP Daemon starting...")
	rtr := mux.NewRouter()

	mod := rtr.PathPrefix("/modules").Subrouter()
	mod.Methods("GET").Path("/").HandlerFunc(makeHandler(handleModuleList))
	mod.Methods("POST").Path("/").HandlerFunc(makeHandler(handleModulePost))
	mod.Methods("GET").Path("/{moduleId}").HandlerFunc(makeHandler(handleModuleGet))
	mod.Methods("PUT").Path("/{moduleId}").HandlerFunc(makeHandler(handleModulePut))
	mod.Methods("DELETE").Path("/{moduleId}").HandlerFunc(makeHandler(handleModuleDelete))

	tbl := mod.PathPrefix("/{moduleId}/tables").Subrouter()
	tbl.Methods("GET").Path("/").HandlerFunc(makeHandler(handleModuleTableList))
	tbl.Methods("GET").Path("/{tableId}").HandlerFunc(makeHandler(handleModuleTableGet))

	ifc := mod.PathPrefix("/{moduleId}/interfaces").Subrouter()
	ifc.Methods("GET").Path("/").HandlerFunc(makeHandler(handleModuleInterfaceList))
	ifc.Methods("GET").Path("/{interfaceId}").HandlerFunc(makeHandler(handleModuleInterfaceGet))

	ent := tbl.PathPrefix("/{tableId}/entries").Subrouter()
	ent.Methods("GET").Path("/").HandlerFunc(makeHandler(handleModuleTableEntryList))
	ent.Methods("POST").Path("/").HandlerFunc(makeHandler(handleModuleTableEntryPost))
	ent.Methods("GET").Path("/{entryId}").HandlerFunc(makeHandler(handleModuleTableEntryGet))
	ent.Methods("PUT").Path("/{entryId}").HandlerFunc(makeHandler(handleModuleTableEntryPut))
	ent.Methods("DELETE").Path("/{entryId}").HandlerFunc(makeHandler(handleModuleTableEntryDelete))

	con := rtr.PathPrefix("/links").Subrouter()
	con.Methods("GET").Path("/").HandlerFunc(makeHandler(handleLinkList))
	con.Methods("POST").Path("/").HandlerFunc(makeHandler(handleLinkPost))
	con.Methods("GET").Path("/{connId}").HandlerFunc(makeHandler(handleLinkGet))
	con.Methods("PUT").Path("/{connId}").HandlerFunc(makeHandler(handleLinkPut))
	con.Methods("DELETE").Path("/{connId}").HandlerFunc(makeHandler(handleLinkDelete))

	return rtr
}
