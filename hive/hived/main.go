// vim: set ts=8:sts=8:sw=8:noet

package main

import (
	"http"

	"github.com/iovisor/iomodules/hive"
)

func main() {
	srv = hive.NewServer()
	http.ListenAndServe(":5000", srv)
}
