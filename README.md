# iomodules
This repo contains IOModule manager (Hover Framework) and plugins

# Hover Framework
Hover framework is a userspace deamon for managing IO/Policy Modules. It exposes REST front-end for dynamically loading, configuring, linking different IO/Policy modules to make a network topology.

# Requirements
* google go version 1.4 or greater
* docker for some of the tests
* BCC

# Installing Hover Framework
```bash
# prereqs
# make sure you have exported $GOPATH to your workspace directory.
go get github.com/vishvananda/netns
go get github.com/willf/bitset
# to pull customized fork of netlink
go get github.com/vishvananda/netlink
cd $GOPATH/src/github.com/vishvananda/netlink
git remote add drzaeus77 https://github.com/drzaeus77/netlink
git fetch drzaeus77
git reset --hard drzaeus77/master

go get github.com/iovisor/iomodules/hover
go install github.com/iovisor/iomodules/hover/hoverd
go test -v github.com/iovisor/iomodules/hover/

# run the hoverd binary in standalone mode
sudo $GOPATH/bin/hoverd
```

# Installing gbp
```bash
# prereqs
# make sure you have already installed hover framework
go get github.com/iovisor/iomodules/gbp
sudo -E go test github.com/iovisor/iomodules/gbp
go install github.com/iovisor/iomodules/gbp/gbp

# run the hoverd binary in standalone mode
$GOPATH/bin/gbp -upstream $ODL_SOUTHBOUND_URL
```
