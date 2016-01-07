# iomodules
IOModule manager and plugins

# Requirements
* go version 1.4 or greater
* docker for some of the tests

# Getting started
```bash
# to pull customized fork of netlink
go get github.com/vishvananda/netlink
cd $GOPATH/src/github.com/vishvananda/netlink
git remote add drzaeus77 https://github.com/drzaeus77/netlink
git fetch drzaeus77
git reset --hard drzaeus77/master

go get github.com/iovisor/iomodules/gbp
sudo -E go test github.com/iovisor/iomodules/gbp
go install github.com/iovisor/iomodules/gbp/gbp
$GOPATH/bin/gbp -upstream $ODL_SOUTHBOUND_URL
```
