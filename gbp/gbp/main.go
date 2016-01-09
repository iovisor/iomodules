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

package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/iovisor/iomodules/gbp"
)

var upstreamUrl string
var listenSocket string
var helpFlag bool

func init() {
	const (
		upstreamDefault     = ""
		upstreamHelp        = "Upstream GBP API endpoint URL"
		listenSocketDefault = "192.168.50.100:5001"
		listenSocketHelp    = "address:port to listen for policy updates"
	)
	flag.StringVar(&upstreamUrl, "upstream", upstreamDefault, upstreamHelp)
	flag.StringVar(&listenSocket, "listen", listenSocketDefault, listenSocketHelp)
	flag.BoolVar(&helpFlag, "h", false, "print this help")

	flag.Usage = func() {
		fmt.Printf("Usage: %s -upstream http://www.example.com:8181\n", filepath.Base(os.Args[0]))
		fmt.Printf(" -upstream URL       %s (default=%s)\n", upstreamHelp, upstreamDefault)
		fmt.Printf(" -listen   ADDR:PORT %s (default=%s)\n", listenSocketHelp, listenSocketDefault)
	}
}

func main() {
	flag.Parse()
	if helpFlag {
		flag.Usage()
		os.Exit(0)
	}
	if len(upstreamUrl) == 0 {
		fmt.Println("Missing argument -upstream")
		flag.Usage()
		os.Exit(1)
	}
	notifier := gbp.NewNotifier(upstreamUrl, listenSocket)
	if err := notifier.NotifyEndpointUp(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	srv := gbp.NewServer()
	http.ListenAndServe(listenSocket, srv)
}
