// Copyright 2015 PLUMgrid and others
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

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"

	"github.com/gorilla/mux"
	"github.com/iovisor/iomodules/policy/database"
	"github.com/iovisor/iomodules/policy/log"
	"github.com/iovisor/iomodules/policy/models"
	"github.com/satori/go.uuid"
)

type routeResponse struct {
	statusCode  int
	contentType string
	body        interface{}
}

type PolicyServer struct {
	HandleFunc http.Handler
	Dataplane  dataplane
	Db         database.Database
}
type handlerFunc func(r *http.Request) routeResponse

func makeHandler(fn handlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if r := recover(); r != nil {
				switch err := r.(type) {
				case runtime.Error:
					http.Error(w, "Internal error", http.StatusBadRequest)
					panic(err)
				case error:
					log.Error.Println(err.Error())
					http.Error(w, err.Error(), http.StatusBadRequest)
				default:
					http.Error(w, "Internal error", http.StatusBadRequest)
					panic(r)
				}
			}
		}()

		rsp := fn(r)
		sendReply(w, r, &rsp)
		log.Info.Printf("%s %s %d\n", r.Method, r.URL, rsp.statusCode)
		return
	}
}

func redirect(url string, code int) routeResponse {
	return routeResponse{statusCode: code, body: url}
}

func notFound() routeResponse {
	return routeResponse{statusCode: http.StatusNotFound}
}

func ok() routeResponse {
	return routeResponse{statusCode: http.StatusOK}
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
			log.Info.Printf("Not Found: %s\n", r.URL)
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

func (g *PolicyServer) handleInfoGet(r *http.Request) routeResponse {
	return routeResponse{
		body: &models.InfoEntry{
			Id: g.Dataplane.Id(),
		},
	}
}

func (g *PolicyServer) handlePolicyList(r *http.Request) routeResponse {
	policies, err := g.Policies()
	if err != nil {
		panic(err)
	}
	return routeResponse{body: policies}
}

func (g *PolicyServer) handlePolicyPost(r *http.Request) routeResponse {
	var req models.Policy
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		panic(err)
	}
	err = g.AddPolicy(&req)
	if err != nil {
		panic(err)
	}
	return routeResponse{body: req}
}

func (g *PolicyServer) handlePolicyGet(r *http.Request) routeResponse {
	id := getRequestVar(r, "policyId")
	policy, err := g.GetPolicy(id)
	if err != nil {
		panic(err)
	}
	return routeResponse{body: policy}
}

func (g *PolicyServer) handlePolicyPut(r *http.Request) routeResponse {
	return notFound()
}

func (g *PolicyServer) handlePolicyDelete(r *http.Request) routeResponse {

	id := getRequestVar(r, "policyId")
	err := g.DeletePolicy(id)
	if err != nil {
		panic(err)
	}
	return ok()
}

func (g *PolicyServer) handleEndpointList(r *http.Request) routeResponse {
	entries, err := g.Endpoints()
	if err != nil {
		panic(err)
	}
	return routeResponse{body: entries}
}

func (g *PolicyServer) handleEndpointPost(r *http.Request) routeResponse {

	var req models.EndpointEntry
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		panic(err)
	}
	if err := g.AddEndpoint(&req); err != nil {
		panic(err)
	}
	return routeResponse{body: req}
}

func (g *PolicyServer) handleEndpointGet(r *http.Request) routeResponse {
	id := getRequestVar(r, "endpointId")
	endpoint, err := g.GetEndpoint(id)
	if err != nil {
		panic(err)
	}
	return routeResponse{body: endpoint}
}

func (g *PolicyServer) handleEndpointPut(r *http.Request) routeResponse {
	return notFound()
}
func (g *PolicyServer) handleEndpointDelete(r *http.Request) routeResponse {

	id := getRequestVar(r, "endpointId")
	err := g.DeleteEndpoint(id)
	if err != nil {
		panic(err)
	}
	return ok()
}

func (g *PolicyServer) Policies() ([]models.Policy, error) {
	policies, err := g.Db.Policies()
	if err != nil {
		return nil, fmt.Errorf("get policies from Db: %s", err)
	}
	return policies, err
}

func (g *PolicyServer) Endpoints() ([]models.EndpointEntry, error) {
	endpoints, err := g.Db.Endpoints()
	if err != nil {
		return nil, fmt.Errorf("get endpoints from Db: %s", err)
	}
	return endpoints, nil
}

func (g *PolicyServer) EndpointGroups() ([]models.EndpointGroup, error) {
	epgs, err := g.Db.EndpointGroups()
	if err != nil {
		return nil, fmt.Errorf("get epgs from Db: %s", err)
	}
	return epgs, nil
}

func (g *PolicyServer) AddPolicy(policy *models.Policy) error {

	sepg, err := g.Db.GetEndpointGroup(policy.SourceEPG)
	if err != nil {
		return fmt.Errorf("get epg from Db: %s", err)
	}
	depg, err := g.Db.GetEndpointGroup(policy.DestEPG)
	if err != nil {
		return fmt.Errorf("get epg from DB: %s", err)
	}
	err = g.Dataplane.AddPolicy(sepg.WireId, policy.SourcePort, depg.WireId, policy.DestPort,
		policy.Protocol, policy.Action)
	if err != nil {
		return fmt.Errorf("add policy to dataplane: %s", err)
	}
	policy.Id = uuid.NewV4().String()
	err = g.Db.AddPolicy(*policy)
	if err != nil {
		return fmt.Errorf("add policy to Db: %s", err)
	}
	return nil
}

func (g *PolicyServer) DeletePolicy(PolicyId string) error {
	policy, err := g.Db.GetPolicy(PolicyId)
	if err != nil {
		return fmt.Errorf("get policy from db: %s", err)
	}
	sepg, err := g.Db.GetEndpointGroup(policy.SourceEPG)
	if err != nil {
		return fmt.Errorf("get epg from Db: %s", err)
	}
	depg, err := g.Db.GetEndpointGroup(policy.DestEPG)
	if err != nil {
		return fmt.Errorf("get epg from Db: %s", err)
	}
	err = g.Dataplane.DeletePolicy(sepg.WireId, policy.SourcePort, depg.WireId, policy.DestPort, policy.Protocol)
	if err != nil {
		return fmt.Errorf("delete policy from dataplane: %s", err)
	}
	err = g.Db.DeletePolicy(PolicyId)
	if err != nil {
		return fmt.Errorf("delete policy from Db: %s", err)
	}
	return nil
}

func (g *PolicyServer) GetPolicy(PolicyId string) (models.Policy, error) {
	policy, err := g.Db.GetPolicy(PolicyId)
	if err != nil {
		return models.Policy{}, fmt.Errorf("get policy from Db: %s", err)
	}
	return policy, nil
}

func (g *PolicyServer) GetEndpoint(EndpointId string) (models.EndpointEntry, error) {
	endpoint, err := g.Db.GetEndpoint(EndpointId)
	if err != nil {
		return models.EndpointEntry{}, fmt.Errorf("get endpoint from Db: %s", err)
	}
	return endpoint, nil
}

func (g *PolicyServer) AddEndpoint(endpoint *models.EndpointEntry) error {
	epg, err := g.Db.GetEndpointGroup(endpoint.EpgId)
	if err != nil {
		return err
	}
	err = g.Dataplane.AddEndpoint(endpoint.Ip, epg.Epg, epg.WireId)
	if err != nil {
		return fmt.Errorf("add endpoint to dataplane: %s", err)
	}
	endpoint.Id = uuid.NewV4().String()
	err = g.Db.AddEndpoint(*endpoint)
	if err != nil {
		return fmt.Errorf("add endpoint to Db: %s", err)
	}
	return nil
}

func (g *PolicyServer) DeleteEndpoint(EpId string) error {

	endpoint, err := g.Db.GetEndpoint(EpId)
	if err != nil {
		return fmt.Errorf("Delete endpoint: %s", err)
	}
	err = g.Dataplane.DeleteEndpoint(endpoint.Ip)
	if err != nil {
		return fmt.Errorf("delete endpoint from dataplane: %s", err)
	}
	err = g.Db.DeleteEndpoint(EpId)
	if err != nil {
		return fmt.Errorf("delete endpoint from Db: %s", err)
	}
	return nil
}

func (g *PolicyServer) HandleEndpointGroupList(r *http.Request) routeResponse {
	groups, err := g.EndpointGroups()
	if err != nil {
		panic(err)
	}
	return routeResponse{body: groups}
}

func (g *PolicyServer) AddEndpointGroup(epg *models.EndpointGroup) error {
	epg.Id = uuid.NewV4().String()
	err := g.Db.AddEndpointGroup(*epg)
	if err != nil {
		return fmt.Errorf("add epg to Db: %s", err)
	}
	return nil
}
func (g *PolicyServer) HandleEndpointGroupPost(r *http.Request) routeResponse {
	var epg models.EndpointGroup
	if err := json.NewDecoder(r.Body).Decode(&epg); err != nil {
		panic(err)
	}
	g.AddEndpointGroup(&epg)
	return routeResponse{body: epg}
}

func (g *PolicyServer) DeleteEndpointGroup(EpgId string) error {
	//epg, err := g.Db.GetEndpointGroup(EpgId)
	//if err != nil {
	//	return fmt.Errorf("Delete epg from db: %s", err)
	//}
	//TODO : make sure epg is only deleted if references are nil
	err := g.Db.DeleteEndpointGroup(EpgId)
	if err != nil {
		return fmt.Errorf("Delete epg from db:%s", err)
	}
	return nil
}

func (g *PolicyServer) HandleEndpointGroupDelete(r *http.Request) routeResponse {

	EpgId := getRequestVar(r, "EpgId")
	err := g.DeleteEndpointGroup(EpgId)
	if err != nil {
		panic(err)
	}
	return ok()
}

func (g *PolicyServer) GetEndpointGroup(EpgId string) (models.EndpointGroup, error) {
	epg, err := g.Db.GetEndpointGroup(EpgId)
	if err != nil {
		return epg, fmt.Errorf("get epg from Db: %s", err)
	}
	return epg, nil
}

func (g *PolicyServer) HandleEndpointGroupGet(r *http.Request) routeResponse {
	EpgId := getRequestVar(r, "EpgId")
	epg, err := g.GetEndpointGroup(EpgId)
	if err != nil {
		panic(err)
	}
	return routeResponse{body: epg}
}

func (g *PolicyServer) HandleEndpointGroupPut(r *http.Request) routeResponse {
	return notFound()
}

func (g *PolicyServer) Handler() http.Handler {
	return g.HandleFunc
}

func NewServer(dataplaneUri string, sqlUrl string) (*PolicyServer, error) {
	log.Info.Println("Policy module starting")
	rtr := mux.NewRouter()

	g := &PolicyServer{
		HandleFunc: rtr,
		Dataplane:  NewDataplane(),
	}

	err := g.Dataplane.Init(dataplaneUri)

	if err != nil {
		return nil, err
	}

	g.Db, err = database.Init(sqlUrl)
	rtr.Methods("GET").Path("/info").HandlerFunc(makeHandler(g.handleInfoGet))

	pol := rtr.PathPrefix("/policies").Subrouter()
	pol.Methods("POST").Path("/").HandlerFunc(makeHandler(g.handlePolicyPost))
	pol.Methods("GET").Path("/").HandlerFunc(makeHandler(g.handlePolicyList))
	pol.Methods("GET").Path("/{policyId}").HandlerFunc(makeHandler(g.handlePolicyGet))
	pol.Methods("PUT").Path("/{policyId}").HandlerFunc(makeHandler(g.handlePolicyPut))
	pol.Methods("DELETE").Path("/{policyId}").HandlerFunc(makeHandler(g.handlePolicyDelete))
	end := rtr.PathPrefix("/endpoints").Subrouter()
	end.Methods("POST").Path("/").HandlerFunc(makeHandler(g.handleEndpointPost))
	end.Methods("GET").Path("/").HandlerFunc(makeHandler(g.handleEndpointList))
	end.Methods("GET").Path("/{endpointId}").HandlerFunc(makeHandler(g.handleEndpointGet))
	end.Methods("PUT").Path("/{endpointId}").HandlerFunc(makeHandler(g.handleEndpointPut))
	end.Methods("DELETE").Path("/{endpointId}").HandlerFunc(makeHandler(g.handleEndpointDelete))

	epg := rtr.PathPrefix("/epg").Subrouter()
	epg.Methods("POST").Path("/").HandlerFunc(makeHandler(g.HandleEndpointGroupPost))
	epg.Methods("GET").Path("/").HandlerFunc(makeHandler(g.HandleEndpointGroupList))
	epg.Methods("GET").Path("/{EpgId}").HandlerFunc(makeHandler(g.HandleEndpointGroupGet))
	epg.Methods("PUT").Path("/{EpgId}").HandlerFunc(makeHandler(g.HandleEndpointGroupPut))
	epg.Methods("DELETE").Path("/{EpgId}").HandlerFunc(makeHandler(g.HandleEndpointGroupDelete))
	// new routes go here

	return g, nil
}
