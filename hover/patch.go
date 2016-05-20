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

// vim: set ts=8:sts=8:sw=8:noet

package hover

import (
	"fmt"
	"syscall"

	"github.com/vishvananda/netlink"
)

func ensureQdisc(link netlink.Link, qdiscType string, handle, parent uint32) (netlink.Qdisc, error) {
	qds, err := netlink.QdiscList(link)
	if err != nil {
		return nil, err
	}
	for _, q := range qds {
		if q.Attrs().Handle == handle {
			//Debug.Printf("Found existing ingress qdisc %x\n", q.Attrs().Handle)
			return q, nil
		}
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    handle,
			Parent:    parent,
		},
		QdiscType: qdiscType,
	}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		return nil, fmt.Errorf("failed ensuring qdisc: %v", err)
	}
	return qdisc, nil
}

func ensureIngressFd(link netlink.Link, fd int) error {
	q, err := ensureQdisc(link, "ingress", netlink.MakeHandle(0xffff, 0), netlink.HANDLE_INGRESS)
	if err != nil {
		return err
	}
	fHandle := netlink.MakeHandle(0, 1)
	filter := &netlink.U32{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    q.Attrs().Handle,
			Priority:  1,
			Protocol:  syscall.ETH_P_ALL,
		},
		Actions: []netlink.Action{
			&netlink.BpfAction{Fd: fd, Name: "bpf1"},
		},
		ClassId: fHandle,
	}
	filters, err := netlink.FilterList(link, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return fmt.Errorf("failed fetching ingress filter list: %s", err)
	}
	for _, f := range filters {
		if f, ok := f.(*netlink.U32); ok {
			if f.ClassId == fHandle {
				return nil
			}
		}
	}
	if err := netlink.FilterAdd(filter); err != nil {
		return fmt.Errorf("failed adding ingress filter: %s", err)
	}
	//Debug.Printf("ensureIngressFd(%s) success\n", link.Attrs().Name)
	return nil
}

func ensureEgressFd(link netlink.Link, fd int) error {
	q, err := ensureQdisc(link, "fq_codel", netlink.MakeHandle(1, 0), netlink.HANDLE_ROOT)
	if err != nil {
		return err
	}
	fHandle := netlink.MakeHandle(0, 2)
	filter := &netlink.U32{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    q.Attrs().Handle,
			Priority:  1,
			Protocol:  syscall.ETH_P_ALL,
		},
		Actions: []netlink.Action{
			&netlink.BpfAction{Fd: fd, Name: "bpf1"},
		},
		ClassId: fHandle,
	}
	filters, err := netlink.FilterList(link, netlink.HANDLE_MIN_EGRESS)
	if err != nil {
		return fmt.Errorf("failed fetching egress filter list: %s", err)
	}
	for _, f := range filters {
		if f, ok := f.(*netlink.U32); ok {
			if f.ClassId == fHandle {
				return nil
			}
		}
	}
	if err := netlink.FilterAdd(filter); err != nil {
		return fmt.Errorf("failed adding egress filter: %v", err)
	}
	return nil
}
