package ofnet

import (
	"fmt"
	"net"

	log "github.com/Sirupsen/logrus"
	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/libOpenflow/protocol"
	"github.com/contiv/ofnet/ofctrl"
	cmap "github.com/streamrail/concurrent-map"
)

type VlanArpLearnerBridge struct {
	agent    *OfnetAgent
	ofSwitch *ofctrl.OFSwitch

	inputTable           *ofctrl.Table
	vlanTable            *ofctrl.Table
	nmlTable             *ofctrl.Table
	localArpRedirectFlow *ofctrl.Flow
	fromUplinkFlow       map[uint32]*ofctrl.Flow
	uplinkPortDb         cmap.ConcurrentMap

	policyAgent *PolicyAgent
}

func NewVlanArpLearnerBridge(agent *OfnetAgent) *VlanArpLearnerBridge {
	vlanArpLearner := new(VlanArpLearnerBridge)
	vlanArpLearner.agent = agent
	vlanArpLearner.fromUplinkFlow = make(map[uint32]*ofctrl.Flow)
	vlanArpLearner.uplinkPortDb = cmap.New()
	vlanArpLearner.policyAgent = NewPolicyAgent(agent, nil)

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

func (self *VlanArpLearnerBridge) setUpFromUplinkFlow(ofPort uint32) error {
	// Add uplink port redirect flow: redirect to normalLookupFlow.
	fromUplinkFlow, err := self.vlanTable.NewFlow(ofctrl.FlowMatch{
		Priority:  FLOW_MATCH_PRIORITY + 1,
		InputPort: ofPort,
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
	self.fromUplinkFlow[ofPort] = fromUplinkFlow

	return nil
}

func (self *VlanArpLearnerBridge) AddUplink(uplinkPort *PortInfo) error {
	var err error
	for _, link := range uplinkPort.MbrLinks {
		err = self.setUpFromUplinkFlow(link.OfPort)
		if err != nil {
			return err
		}
	}
	self.uplinkPortDb.Set(uplinkPort.Name, uplinkPort)

	return nil
}

func (self *VlanArpLearnerBridge) UpdateUplink(uplinkName string, update PortUpdates) error {
	return nil
}

func (self *VlanArpLearnerBridge) RemoveUplink(uplinkName string) error {
	uplinkPort := self.GetUplink(uplinkName)
	if uplinkPort == nil {
		err := fmt.Errorf("Could not get uplink with name: %s", uplinkName)
		return err
	}

	for _, link := range uplinkPort.MbrLinks {
		if fromUplinkFlow, ok := self.fromUplinkFlow[link.OfPort]; ok {
			fromUplinkFlow.Delete()
			delete(self.fromUplinkFlow, link.OfPort)
		}
	}
	self.uplinkPortDb.Remove(uplinkName)

	return nil
}

func (self *VlanArpLearnerBridge) GetUplink(uplinkID string) *PortInfo {
	uplink, ok := self.uplinkPortDb.Get(uplinkID)
	if !ok {
		return nil
	}
	return uplink.(*PortInfo)
}

func (self *VlanArpLearnerBridge) initFgraph() error {
	sw := self.ofSwitch

	self.inputTable = sw.DefaultTable()
	self.vlanTable, _ = sw.NewTable(VLAN_TBL_ID)
	self.nmlTable, _ = sw.NewTable(MAC_DEST_TBL_ID)

	err := self.policyAgent.InitTables(MAC_DEST_TBL_ID)
	if err != nil {
		log.Fatalf("Error when installing Policy table. Err: %v", err)
		return err
	}

	inputMissFlow, _ := self.inputTable.NewFlow(ofctrl.FlowMatch{
		Priority: FLOW_MISS_PRIORITY,
	})
	inputMissFlow.Next(self.vlanTable)

	tier0PolicyTable := sw.GetTable(POLICY_TIER0_TBL_ID)
	vlanMissFlow, _ := self.vlanTable.NewFlow(ofctrl.FlowMatch{
		Priority: FLOW_MISS_PRIORITY,
	})
	vlanMissFlow.Next(tier0PolicyTable)

	self.setArpRedirectFlow()

	if self.uplinkPortDb.Count() != 0 {
		for uplinkObj := range self.uplinkPortDb.IterBuffered() {
			uplink := uplinkObj.Val.(*PortInfo)
			for _, link := range uplink.MbrLinks {
				self.setUpFromUplinkFlow(link.OfPort)
			}
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
	self.policyAgent.SwitchConnected(sw)
	self.initFgraph()
}

func (self *VlanArpLearnerBridge) SwitchDisconnected(sw *ofctrl.OFSwitch) {
	self.policyAgent.SwitchDisconnected(sw)
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
		log.Errorf("controller received non arp packet error.")
		return
	}
}

func (self *VlanArpLearnerBridge) processArp(pkt protocol.Ethernet, inPort uint32) {
	var isLearning bool
	switch t := pkt.Data.(type) {
	case *protocol.ARP:
		var arpIn protocol.ARP = *t

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
	updatedOfPortInfo := make(map[uint32][]net.IP)
	updatedOfPortInfo[inPort] = []net.IP{arpIn.IPSrc}
	self.agent.ofPortIpAddressUpdateChan <- updatedOfPortInfo

	endpointInfo := &endpointInfo{
		OfPort:  inPort,
		IpAddr:  arpIn.IPSrc,
		MacAddr: arpIn.HWSrc,
	}
	self.agent.localEndpointInfo[inPort] = endpointInfo
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
func (self *VlanArpLearnerBridge) GetPolicyAgent() *PolicyAgent {
	return self.policyAgent
}
