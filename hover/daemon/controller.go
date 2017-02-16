// Copyright 2017 Politecnico di Torino
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
package daemon

import (
	"encoding/gob"
	"fmt"
	"io"
	"os/exec"
	"net"
	"strconv"

	"github.com/iovisor/iomodules/hover"
	"github.com/iovisor/iomodules/hover/api"
	"github.com/iovisor/iomodules/hover/bpf"
	"github.com/iovisor/iomodules/hover/canvas"
	"github.com/iovisor/iomodules/hover/util"

	"github.com/songgao/water"

	"github.com/vishvananda/netlink"
)

type PacketIn struct {
	Module_id  uint16
	Port_id    uint16
	Packet_len uint16
	Reason     uint16
	Data       []byte
}

const (
	INGRESS = 0
	EGRESS = 1
)

type PacketOut struct {
	Module_id  uint16
	Port_id    uint16
	Sense      uint16 /* ingress = 0, egress = 1 */
	Data       []byte
}

type Controller struct {
	txModule     *canvas.BpfAdapter
	rxModule     *canvas.BpfAdapter
	link         netlink.Link
	ifc          *water.Interface
	conn         net.Conn
	connected    bool
	encoder     *gob.Encoder
	g            canvas.Graph
	// Index used to send packets to the dataplane
	p_index uint32
}

func NewController(g canvas.Graph) (cm *Controller, err error) {
	cm = &Controller{}

	config := water.Config{
		DeviceType: water.TAP,
	}

	ifc, err2 := water.New(config)
	if err2 != nil {
		err = fmt.Errorf("ControllerModule: unable to create tap interface")
		return
	}

	link, err2 := netlink.LinkByName(ifc.Name())
	if err2 != nil {
		err = fmt.Errorf("ControllerModule: unable to find tap interface")
		return
	}

	// avoid ipv6 being assigned to the tap interface
	_, err1 := exec.Command("ip", "link", "set", "dev", ifc.Name(), "addrgenmode", "none").Output()
	if err1 != nil {
		err = fmt.Errorf("ControllerModule: unable to configure tap interface")
		return
	}

	err = netlink.LinkSetUp(link)
	if err != nil {
		return
	}

	// Create tx module
	idTx := util.NewUUID4()
	cflagsTx := []string{
		fmt.Sprintf("-DCONTROLLER_INTERFACE_ID=%d", link.Attrs().Index),
	}

	bpfTx := bpf.NewBpfModule(bpf.ControllerModuleTxC, cflagsTx)
	if bpfTx == nil {
		err = fmt.Errorf("ControllerModule: unable to create TX module")
		return
	}

	cm.txModule = canvas.NewBpfAdapter(idTx, "controllerTX", bpfTx)

	fdTx, err2 := bpfTx.LoadNet("controller_module_tx")
	if err2 != nil {
		err = fmt.Errorf("ControllerModule: unable to load TX module: %s", err2)
		return
	}
	// FIXME: is it necessary to duplicate the fd?
	cm.txModule.SetFD(fdTx)

	// Create rx module
	idRx := util.NewUUID4()

	bpfRx := bpf.NewBpfModule(bpf.ControllerModuleRxC, []string{})
	if bpfRx == nil {
		err = fmt.Errorf("ControllerModule: unable to create RX module")
		return
	}

	cm.rxModule = canvas.NewBpfAdapter(idRx, "controllerRX", bpfRx)

	fdRx, err3 := bpfRx.LoadNet("controller_module_rx")
	if err3 != nil {
		err = fmt.Errorf("ControllerModule: unable to load RX module")
		return
	}
	// FIXME: is it necessary to duplicate the fd?
	cm.rxModule.SetFD(fdRx)

	err = hover.EnsureIngressFd(link, fdRx)

	cm.ifc = ifc
	cm.g = g

	return
}

func (c *Controller) Close() {
	// TODO: Implement
}

func (c *Controller) Run() {
	packet := make([]byte, 2000)
	var index uint32 = 0;
	for {
		n, err := c.ifc.Read(packet)
		index++
		index %= 1024

		if err != nil {
			Error.Println("Error reading from controller iface")
			continue
		}

		if c.connected {

			//index_tbl := c.txModule.Table("index_map")
			//if index_tbl == nil {
			//	panic("index table not found")
			//}
            //
			//index, ok := index_tbl.Get("0")
			//if !ok {
			//	panic("index not found on index table")
			//}

			md_tbl := c.txModule.Table("md_map_tx")
			if md_tbl == nil {
				panic("md_map table not found")
			}

			md, ok := md_tbl.Get(strconv.FormatUint(uint64(index), 10))
			if !ok {
				panic("md entry not found")
			}

			p := &PacketIn{}
			_, err := fmt.Sscanf(md.(api.ModuleTableEntry).Value, "{ 0x%x 0x%x 0x%x 0x%x }",
				&p.Module_id, &p.Port_id, &p.Packet_len, &p.Reason)
			if err != nil {
				panic("Error parsing packet")
			}

			if p.Packet_len != uint16(n) {
				panic("Length does not match")
			}

			p.Data = packet[:n]

			// should the packet be processed locally or sent to controller?
			if p.Reason > bpf.RESERVED_REASON_MIN {
				c.processLocalPacket(p)
			} else {
				c.encoder.Encode(p)
			}
		}
	}
}

func (c *Controller) RunExternal() (err error) {

	dec := gob.NewDecoder(c.conn)

	for {
		p := &PacketOut{}
		err1 := dec.Decode(p)
		if err1 == io.EOF {
			Info.Printf("Controller: Remote Controller Disconnected")
			return nil
		} else if err1 != nil {
			continue
		}

		// final destination of the packet
		var ifc uint16
		var module_id uint16

		if p.Sense == INGRESS {
			ifc = p.Port_id
			module_id = p.Module_id
		} else if p.Sense == EGRESS {
			node := c.g.Node(int(p.Module_id))
			if node == nil {
				Warn.Printf("Controller: Bad module_id received")
				continue
			}

			to := c.g.From(node)
			found := false
			for _, n := range to {
				e := c.g.Edge(node, n)
				if uint16(e.(canvas.Edge).F().I) == p.Port_id {
					module_id = uint16(e.(canvas.Edge).T().N)
					ifc = uint16(e.(canvas.Edge).T().I)
					found = true
					break
				}
			}

			if !found {
				Warn.Printf("Controller: Next Module not found")
				continue;
			}

		} else {
			Warn.Printf("Controller: Bad sense received")
			continue
		}

		c.sendPacketToIOModule(module_id, ifc, p.Data)
	}
	return nil
}

func (c *Controller) ConnectToRemoteController(addr string) (err error) {
	c.conn, err = net.Dial("tcp", addr)
	if err != nil {
		Error.Println("Connection error", err)
		return err
	}

	c.encoder = gob.NewEncoder(c.conn)
	c.connected = true

	go c.RunExternal() //process packets sent by the controller

	return
}

func (c *Controller) sendPacketToIOModule(module_id uint16, ifc uint16, data []byte) (err error) {
	c.p_index++
	c.p_index %= bpf.MD_MAP_SIZE

	// save metadata
	md_tbl := c.rxModule.Table("md_map_rx")
	if md_tbl == nil {
		panic("md_map table not found")
	}

	value := fmt.Sprintf("{0x%x 0x%x}", module_id, ifc)
	err = md_tbl.Set(strconv.FormatUint(uint64(c.p_index), 10), value)
	if err != nil {
		fmt.Printf("error is: ", err)
		panic("error saving md")
	}

	_, err = c.ifc.Write(data)
	if err != nil {
		Error.Printf("error writing  packet: %s", err)
		panic("error writing  packet")
	}
	return
}

func (c *Controller) processLocalPacket(p *PacketIn) {
	switch p.Reason {
	case bpf.PKT_BROADCAST:
		c.broadcastPacket(p)
	default:
		Warn.Printf("Invalid reason: %d", p.Reason)
	}
}

func (c *Controller) broadcastPacket(p *PacketIn) {
	node := c.g.Node(int(p.Module_id))
	if node == nil {
		Warn.Printf("Controller: Bad module_id received")
		return
	}

	to := c.g.From(node)
	for _, n := range to {
		e := c.g.Edge(node, n)
		// Do not broadcast packet on ingress ifc
		if uint16(e.(canvas.Edge).F().I) == p.Port_id {
			continue
		}
		module_id := uint16(e.(canvas.Edge).T().N)
		ifc := uint16(e.(canvas.Edge).T().I)
		c.sendPacketToIOModule(module_id, ifc, p.Data)
	}
}
