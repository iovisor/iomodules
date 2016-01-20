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

package gbp

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"net/http"
	"regexp"
	"runtime"
)

var reqUriRegex = regexp.MustCompile(`^/restconf/operational/resolved-policy:resolved-policies/resolved-policy(/[[:graph:]]+){4}`)

type routeResponse struct {
	statusCode  int
	contentType string
	body        interface{}
}

type GbpServer struct {
	handler     http.Handler
	upstreamUri string
	dataplane   *Dataplane
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
					Error.Println(err.Error())
					http.Error(w, err.Error(), http.StatusBadRequest)
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

type infoEntry struct {
	Id string `json:"id"`
}

func (g *GbpServer) handleInfoGet(r *http.Request) routeResponse {
	return routeResponse{
		body: &infoEntry{
			Id: g.dataplane.Id(),
		},
	}
}

func (g *GbpServer) handlePolicyList(r *http.Request) routeResponse {
	return notFound()
}

type createPolicyRequestUri struct {
	Uri string `json:"resolved-policy-uri"`
}

type createPolicyRequest struct {
	ResolvedPolicy *ResolvedPolicy `json:"resolved-policies"`
}

func (g *GbpServer) handlePolicyPost(r *http.Request) routeResponse {
	var req createPolicyRequestUri
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		panic(err)
	}

	/* Received URI to fetch policy for relevant endpoints to this Agent */
	reqUri := req.Uri
	if reqUriRegex.MatchString(reqUri) == false {
		panic(fmt.Errorf("Uri returned: %s is not in format `^/restconf/operational/resolved-policy:resolved-policies/resolved-policy/<string>/<string>/<string>/<string>/`", reqUri))
	}

	/* Authenticate */
	Debug.Printf(g.upstreamUri + reqUri)
	reqGet, err := http.NewRequest("GET", g.upstreamUri+reqUri, nil)
	reqGet.SetBasicAuth("admin", "admin")

	client := http.Client{}
	resp, err := client.Do(reqGet)
	if err != nil {
		Error.Printf("Error : %s", err)
	}
	var req2 ResolvedPolicy

	if err := json.NewDecoder(resp.Body).Decode(&req2); err != nil {
		panic(err)
	}

	for _, policy := range req2.ResolvedPolicies {
		if err := g.dataplane.ParsePolicy(policy); err != nil {
			panic(err)
		}
	}
	return routeResponse{}
}
func (g *GbpServer) handlePolicyGet(r *http.Request) routeResponse {
	return notFound()
}
func (g *GbpServer) handlePolicyPut(r *http.Request) routeResponse {
	return notFound()
}
func (g *GbpServer) handlePolicyDelete(r *http.Request) routeResponse {
	return notFound()
}

func (g *GbpServer) handleEndpointList(r *http.Request) routeResponse {
	entries := []*EndpointEntry{}
	for endpoint := range g.dataplane.Endpoints() {
		entries = append(entries, endpoint)
	}
	return routeResponse{body: entries}
}

func (g *GbpServer) handleEndpointPost(r *http.Request) routeResponse {
	var req EndpointEntry
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		panic(err)
	}
	if err := g.dataplane.AddEndpoint(req.Ip, req.Tenant, req.Epg); err != nil {
		panic(err)
	}
	return routeResponse{body: req}
}
func (g *GbpServer) handleEndpointGet(r *http.Request) routeResponse {
	return notFound()
}
func (g *GbpServer) handleEndpointPut(r *http.Request) routeResponse {
	return notFound()
}
func (g *GbpServer) handleEndpointDelete(r *http.Request) routeResponse {
	return notFound()
}

func (g *GbpServer) Handler() http.Handler {
	return g.handler
}

func NewServer(upstreamUri, dataplaneUri string) (*GbpServer, error) {
	Info.Println("GBP module starting")
	rtr := mux.NewRouter()

	g := &GbpServer{
		handler:     rtr,
		upstreamUri: upstreamUri,
		dataplane:   NewDataplane(":memory:"),
	}
	if err := g.dataplane.Init(dataplaneUri); err != nil {
		return nil, err
	}

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

	// new routes go here

	return g, nil
}
