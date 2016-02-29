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

package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/iovisor/iomodules/dnsmon"
)

var listenSocket string
var hoverUrl string
var helpFlag bool

func init() {
	const (
		hoverDefault        = ""
		hoverHelp           = "Local hover URL"
		listenSocketDefault = "127.0.0.1:5001"
		listenSocketHelp    = "address:port to listen for updates"
	)
	flag.StringVar(&hoverUrl, "hover", hoverDefault, hoverHelp)
	flag.StringVar(&listenSocket, "listen", listenSocketDefault, listenSocketHelp)
	flag.BoolVar(&helpFlag, "h", false, "print this help")

	flag.Usage = func() {
		fmt.Printf("Usage: %s -hover http://localhost:5000\n", filepath.Base(os.Args[0]))
		fmt.Printf(" -hover   URL       %s (default=%s)\n", hoverHelp, hoverDefault)
		fmt.Printf(" -listen  ADDR:PORT %s (default=%s)\n", listenSocketHelp, listenSocketDefault)
	}
}

func main() {
	flag.Parse()
	if helpFlag {
		flag.Usage()
		os.Exit(0)
	}
	if len(hoverUrl) == 0 {
		fmt.Println("Missing argument -hover")
		flag.Usage()
		os.Exit(1)
	}
	srv, err := dnsmon.NewServer(hoverUrl)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	dnsmon.Info.Printf("DnsMon Server listening on %s\n", listenSocket)
	http.ListenAndServe(listenSocket, srv.Handler())
}
