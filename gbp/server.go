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
	"strings"
)

type routeResponse struct {
	statusCode  int
	contentType string
	body        interface{}
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

func handlePolicyList(r *http.Request) routeResponse {
	return notFound()
}

type createPolicyRequestUri struct {
	Uri string `json:"resolved-policy-uri"`
}

type createPolicyRequest struct {
	ResolvedPolicy *ResolvedPolicy `json:"resolved-policies"`
}

func handlePolicyPost(r *http.Request) routeResponse {
	var req createPolicyRequestUri
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		panic(err)
	}

	/* Received URI to fetch policy for relevant endpoints to this Agent */
	reqUri := req.Uri
	reqUriRegex, err := regexp.Compile(`^/restconf/operational/resolved-policy:resolved-policies/resolved-policy/([[:graph:]]+/){4}`)
	if reqUriRegex.MatchString(reqUri) == false {
		Info.Printf("Uri returned: %s is not in format `^/restconf/operational/resolved-policy:resolved-policies/resolved-policy/<string>/<string>/<string>/<string>/`", reqUri)
		return routeResponse{}
	}

	requesterIp := r.RemoteAddr[:strings.IndexAny(r.RemoteAddr, ":")]
	/* Authenticate */
	// TODO: Replace server IP/port with main:upstreamUrl
	reqGet, err := http.NewRequest("GET", "http://"+requesterIp+":8181"+reqUri, nil)
	reqGet.SetBasicAuth("admin", "admin")

	client := http.Client{}
	resp, err := client.Do(reqGet)
	if err != nil {
		fmt.Printf("Error : %s", err)
	}
	var req2 ResolvedPolicy

	if err := json.NewDecoder(resp.Body).Decode(&req2); err != nil {
		panic(err)
	}

	for _, policy := range req2.ResolvedPolicies {
		if err := dataplane.ParsePolicy(policy); err != nil {
			panic(err)
		}
	}
	return routeResponse{}
}
func handlePolicyGet(r *http.Request) routeResponse {
	return notFound()
}
func handlePolicyPut(r *http.Request) routeResponse {
	return notFound()
}
func handlePolicyDelete(r *http.Request) routeResponse {
	return notFound()
}

func NewServer() http.Handler {
	Info.Println("GBP module starting")
	rtr := mux.NewRouter()

	pol := rtr.PathPrefix("/policies").Subrouter()
	pol.Methods("POST").Path("/").HandlerFunc(makeHandler(handlePolicyPost))
	pol.Methods("GET").Path("/").HandlerFunc(makeHandler(handlePolicyList))
	pol.Methods("GET").Path("/{policyId}").HandlerFunc(makeHandler(handlePolicyGet))
	pol.Methods("PUT").Path("/{policyId}").HandlerFunc(makeHandler(handlePolicyPut))
	pol.Methods("DELETE").Path("/{policyId}").HandlerFunc(makeHandler(handlePolicyDelete))

	// new routes go here

	return rtr
}
