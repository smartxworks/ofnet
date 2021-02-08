package ofnet

import (
	"fmt"
	"net"

	log "github.com/Sirupsen/logrus"
	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/libOpenflow/protocol"
	"github.com/contiv/ofnet/ofctrl"
)

type VlanArpLearnerBridge struct {
	agent    *OfnetAgent
	ofSwitch *ofctrl.OFSwitch

	inputTable           *ofctrl.Table
	vlanTable            *ofctrl.Table
	nmlTable             *ofctrl.Table
	uplinkPort           map[uint32]OVSPort
	localArpRedirectFlow *ofctrl.Flow
	uplinkArpFlow        []*ofctrl.Flow

	lynxPolicyAgent *PolicyAgent
}

func NewVlanArpLearnerBridge(agent *OfnetAgent) *VlanArpLearnerBridge {
	vlanArpLearner := new(VlanArpLearnerBridge)
	vlanArpLearner.agent = agent
	vlanArpLearner.uplinkPort = make(map[uint32]OVSPort)
	vlanArpLearner.lynxPolicyAgent = NewPolicyAgent(agent, nil)

	return vlanArpLearner
}

func (self *VlanArpLearnerBridge) setArpRedirectFlow() error {
	// Learn local ovsport originated arp
	sw := self.ofSwitch
	arpRedirectFlow, err := self.inputTable.NewFlow(ofctrl.FlowMatch{
		Priority:  FLOW_MATCH_PRIORITY,
		Ethertype: 0x0806,
	})
	if err != nil {
		log.Errorf("Error when add local endpoint arp redirect flow")
		return err
	}
	arpRedirectFlow.Next(sw.SendToController())
	self.localArpRedirectFlow = arpRedirectFlow

	return nil
}

func (self *VlanArpLearnerBridge) setUplinkArpFlow(ofPort uint32) error {
	// Uplink port originated arp, normal
	uplinkArpFlow, err := self.inputTable.NewFlow(ofctrl.FlowMatch{
		Priority:  FLOW_MATCH_PRIORITY + 1,
		Ethertype: 0x0806,
		InputPort: ofPort,
	})
	if err != nil {
		log.Errorf("Error when add uplink arp flow")
		return err
	}
	uplinkArpFlow.Next(self.nmlTable)
	self.uplinkArpFlow = append(self.uplinkArpFlow, uplinkArpFlow)
	return nil
}

func (self *VlanArpLearnerBridge) AddUplink(uplinkPort *PortInfo) error {
	for _, link := range uplinkPort.MbrLinks {
		err := self.setUplinkArpFlow(link.OfPort)
		if err != nil {
			return err
		}
		// Add uplink port redirect flow: redirect to normalLookupFlow.
		fromUplinkFlow, err := self.vlanTable.NewFlow(ofctrl.FlowMatch{
			Priority:  FLOW_MATCH_PRIORITY,
			InputPort: link.OfPort,
		})
		if err != nil {
			log.Errorf("Error when create vlanTable fromUplinkFlow. Err: %v", err)
			return err
		}
		normalLookupTable := self.ofSwitch.GetTable(MAC_DEST_TBL_ID)
		err = fromUplinkFlow.Next(normalLookupTable)
		if err != nil {
			log.Errorf("Error when create vlanTable fromUplinkFlow nextTable action. Err: %v", err)
			return err
		}
	}

	// TODO Cached uplink related flow

	return nil
}

func (self *VlanArpLearnerBridge) UpdateUplink(uplinkName string, update PortUpdates) error {
	return nil
}

func (self *VlanArpLearnerBridge) RemoveUplink(uplinkName string) error {
	return nil
}

func (self *VlanArpLearnerBridge) initFgraph() error {
	sw := self.ofSwitch

	self.inputTable = sw.DefaultTable()
	self.vlanTable, _ = sw.NewTable(VLAN_TBL_ID)
	self.nmlTable, _ = sw.NewTable(MAC_DEST_TBL_ID)

	err := self.lynxPolicyAgent.InitTables(MAC_DEST_TBL_ID)
	if err != nil {
		log.Fatalf("Error when installing Policy table. Err: %v", err)
		return err
	}

	inputMissFlow, _ := self.inputTable.NewFlow(ofctrl.FlowMatch{
		Priority: FLOW_MISS_PRIORITY,
	})
	inputMissFlow.Next(self.vlanTable)

	tier0PolicyTable := sw.GetTable(TIER0_TBL_ID)
	vlanMissFlow, _ := self.vlanTable.NewFlow(ofctrl.FlowMatch{
		Priority: FLOW_MISS_PRIORITY,
	})
	vlanMissFlow.Next(tier0PolicyTable)

	self.setArpRedirectFlow()
	// TODO Get uplink ofport list and init uplinkArpFlow, for restore
	if len(self.uplinkPort) > 0 {
		for ofPort, _ := range self.uplinkPort {
			self.setUplinkArpFlow(ofPort)
		}
	}

	normalLookupFlow, _ := self.nmlTable.NewFlow(ofctrl.FlowMatch{
		Priority: FLOW_MISS_PRIORITY,
	})
	normalLookupFlow.Next(sw.NormalLookup())

	return nil
}

// Controller appinterface: SwitchConnected, SwichDisConnected, MultipartReply, PacketRcvd
func (self *VlanArpLearnerBridge) SwitchConnected(sw *ofctrl.OFSwitch) {
	self.ofSwitch = sw
	self.lynxPolicyAgent.SwitchConnected(sw)
	self.initFgraph()
}

func (self *VlanArpLearnerBridge) SwitchDisconnected(sw *ofctrl.OFSwitch) {
	self.lynxPolicyAgent.SwitchDisconnected(sw)
	self.ofSwitch = nil
}

func (self *VlanArpLearnerBridge) MultipartReply(sw *ofctrl.OFSwitch, reply *openflow13.MultipartReply) {
}

func (self *VlanArpLearnerBridge) PacketRcvd(sw *ofctrl.OFSwitch, pkt *ofctrl.PacketIn) {

	switch pkt.Data.Ethertype {
	case 0x0806:
		if (pkt.Match.Type == openflow13.MatchType_OXM) &&
			(pkt.Match.Fields[0].Class == openflow13.OXM_CLASS_OPENFLOW_BASIC) &&
			(pkt.Match.Fields[0].Field == openflow13.OXM_FIELD_IN_PORT) {
			// Get the input port number
			switch t := pkt.Match.Fields[0].Value.(type) {
			case *openflow13.InPortField:
				var inPortFld openflow13.InPortField
				inPortFld = *t
				self.processArp(pkt.Data, inPortFld.InPort)
			}
		}
	case protocol.IPv4_MSG: // other type of packet that must processing by controller
	}
}

func (self *VlanArpLearnerBridge) processArp(pkt protocol.Ethernet, inPort uint32) {
	var isLearning bool
	switch t := pkt.Data.(type) {
	case *protocol.ARP:
		var arpIn protocol.ARP = *t
		// TODO process RARP arp.opcode = 3

		// Reinject garp packet
		if arpIn.IPSrc.String() == arpIn.IPDst.String() {
			log.Debugf("Ignorning grap packet")
			return
		}

		localEndpointInfo, ok := self.agent.localEndpointInfo[inPort]
		if !ok {
			log.Infof("local ofport %d related ovsport was't learned", inPort)
			isLearning = true
		}
		if !localEndpointInfo.IpAddr.Equal(arpIn.IPSrc) {
			log.Infof("local ofport %d related endpoint ipaddress update", inPort)
			isLearning = true
		}
		if isLearning {
			self.learnFromArp(arpIn, inPort)
		}
		self.arpNoraml(pkt, inPort)
	}
}

func (self *VlanArpLearnerBridge) learnFromArp(arpIn protocol.ARP, inPort uint32) {
	endpointInfo := &EndPointInfo{
		OfPort:  inPort,
		IpAddr:  arpIn.IPSrc,
		MacAddr: arpIn.HWSrc,
	}
	self.agent.localEndpointInfo[inPort] = endpointInfo
	fmt.Printf("Learned endpoint info: %v", endpointInfo)
}

func (self *VlanArpLearnerBridge) arpNoraml(pkt protocol.Ethernet, inPort uint32) {
	arpIn := pkt.Data.(*protocol.ARP)

	ethPkt := protocol.NewEthernet()
	ethPkt.VLANID = pkt.VLANID
	ethPkt.HWDst = pkt.HWDst
	ethPkt.HWSrc = pkt.HWSrc
	ethPkt.Ethertype = 0x0806
	ethPkt.Data = arpIn

	pktOut := openflow13.NewPacketOut()
	pktOut.InPort = inPort
	pktOut.Data = ethPkt
	pktOut.AddAction(openflow13.NewActionOutput(openflow13.P_NORMAL))

	self.ofSwitch.Send(pktOut)
}

// OfnetDatapath define but not used method
func (self *VlanArpLearnerBridge) MasterAdded(master *OfnetNode) error {
	return nil
}

func (self *VlanArpLearnerBridge) AddLocalEndpoint(endpoint OfnetEndpoint) error {
	return nil
}

func (self *VlanArpLearnerBridge) RemoveLocalEndpoint(endpoint OfnetEndpoint) error {
	return nil
}

func (self *VlanArpLearnerBridge) UpdateLocalEndpoint(ep *OfnetEndpoint, epInfo EndpointInfo) error {
	return nil
}

func (self *VlanArpLearnerBridge) AddEndpoint(endpoint *OfnetEndpoint) error {
	return nil
}

func (self *VlanArpLearnerBridge) RemoveEndpoint(endpoint *OfnetEndpoint) error {
	return nil
}

// AddVtepPort Add virtual tunnel end point.
func (self *VlanArpLearnerBridge) AddVtepPort(portNo uint32, remoteIP net.IP) error {
	return nil
}

// RemoveVtepPort Remove a VTEP port
func (self *VlanArpLearnerBridge) RemoveVtepPort(portNo uint32, remoteIP net.IP) error {
	return nil
}

// AddVlan Add a vlan.
func (self *VlanArpLearnerBridge) AddVlan(vlanID uint16, vni uint32, vrf string) error {
	self.agent.vlanVrfMutex.Lock()
	self.agent.vlanVrf[vlanID] = &vrf
	self.agent.vlanVrfMutex.Unlock()
	self.agent.createVrf(vrf)
	return nil
}

// RemoveVlan Remove a vlan
func (self *VlanArpLearnerBridge) RemoveVlan(vlanID uint16, vni uint32, vrf string) error {
	self.agent.vlanVrfMutex.Lock()
	delete(self.agent.vlanVrf, vlanID)
	self.agent.vlanVrfMutex.Unlock()
	self.agent.deleteVrf(vrf)
	return nil
}

// AddHostPort is not implemented
func (self *VlanArpLearnerBridge) AddHostPort(hp HostPortInfo) error {
	return nil
}

func (self *VlanArpLearnerBridge) InjectGARPs(epgID int) {
	return
}

// RemoveHostPort is not implemented
func (self *VlanArpLearnerBridge) RemoveHostPort(hp uint32) error {
	return nil
}

func (self *VlanArpLearnerBridge) AddSvcSpec(svcName string, spec *ServiceSpec) error {
	return nil
}

// DelSvcSpec removes a service spec from proxy
func (self *VlanArpLearnerBridge) DelSvcSpec(svcName string, spec *ServiceSpec) error {
	return nil
}

func (self *VlanArpLearnerBridge) SvcProviderUpdate(svcName string, providers []string) {
	return
}

func (self *VlanArpLearnerBridge) GetEndpointStats() (map[string]*OfnetEndpointStats, error) {
	return nil, nil
}

func (self *VlanArpLearnerBridge) InspectState() (interface{}, error) {
	return nil, nil
}

// Update global config
func (self *VlanArpLearnerBridge) GlobalConfigUpdate(cfg OfnetGlobalConfig) error {
	return nil
}

//FlushEndpoints flushes endpoints from ovs
func (self *VlanArpLearnerBridge) FlushEndpoints(endpointType int) {
}

func GetUplinkPort(portName string, ofPort uint32, portType string) *PortInfo {
	var port PortInfo
	link := LinkInfo{
		Name:       portName,
		OfPort:     uint32(ofPort),
		LinkStatus: linkDown,
		Port:       &port,
	}
	port = PortInfo{
		Name:       portName,
		Type:       portType,
		LinkStatus: linkDown,
		MbrLinks:   []*LinkInfo{&link},
	}

	return &port
}
