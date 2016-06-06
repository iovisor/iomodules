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

package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/iovisor/iomodules/policy/log"
	"github.com/iovisor/iomodules/policy/server"
)

var helpFlag bool
var dataplaneUrl string
var listenSocketDefault string
var dataplaneHelp string
var listenSocket string

func init() {
	const (
		dataplaneDefault    = ""
		dataplaneHelp       = "Local dataplane URL"
		listenSocketDefault = "127.0.0.1:5001"
		listenSocketHelp    = "address:port to listen for policy updates"
	)
	flag.StringVar(&dataplaneUrl, "dataplane", dataplaneDefault, dataplaneHelp)
	flag.StringVar(&listenSocket, "listen", listenSocketDefault, listenSocketHelp)
	flag.BoolVar(&helpFlag, "h", false, "print this help")

	flag.Usage = func() {
		fmt.Printf(" -dataplane URL      %s (default=%s)\n", dataplaneHelp, dataplaneDefault)
		fmt.Printf(" -listen   ADDR:PORT %s (default=%s)\n", listenSocketHelp, listenSocketDefault)
	}
}

func main() {
	flag.Parse()
	if helpFlag {
		flag.Usage()
		os.Exit(0)
	}
	if len(dataplaneUrl) == 0 {
		fmt.Println("Missing argument -dataplane")
		flag.Usage()
		os.Exit(1)
	}
	p, err := server.NewServer(dataplaneUrl, ":memory:")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	log.Info.Printf("Policy Server listening on %s\n", listenSocket)
	http.ListenAndServe(listenSocket, p.Handler())
}
