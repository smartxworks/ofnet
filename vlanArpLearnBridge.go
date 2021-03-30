package ofnet

import (
	"errors"
	"fmt"
	"net"

	log "github.com/Sirupsen/logrus"
	"github.com/deckarep/golang-set"
	cmap "github.com/streamrail/concurrent-map"

	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/libOpenflow/protocol"
	"github.com/contiv/ofnet/ofctrl"
)

type VlanArpLearnerBridge struct {
	agent    *OfnetAgent
	ofSwitch *ofctrl.OFSwitch

	inputTable         *ofctrl.Table
	ingressSelectTable *ofctrl.Table
	nmlTable           *ofctrl.Table
	arpRedirectFlow    *ofctrl.Flow
	fromUplinkFlow     map[uint32][]*ofctrl.Flow
	fromLocalFlow      []*ofctrl.Flow
	ingressSelectFlow  map[string]*ofctrl.Flow
	uplinkPortDb       cmap.ConcurrentMap

	policyAgent *PolicyAgent
}

func NewVlanArpLearnerBridge(agent *OfnetAgent) *VlanArpLearnerBridge {
	vlanArpLearner := new(VlanArpLearnerBridge)
	vlanArpLearner.agent = agent
	vlanArpLearner.fromUplinkFlow = make(map[uint32][]*ofctrl.Flow)
	vlanArpLearner.ingressSelectFlow = make(map[string]*ofctrl.Flow)
	vlanArpLearner.uplinkPortDb = cmap.New()
	vlanArpLearner.policyAgent = NewPolicyAgent(agent, nil)

	return vlanArpLearner
}

func (self *VlanArpLearnerBridge) installArpRedirectFlow() error {
	// Send all arp packet to openflow controller
	sw := self.ofSwitch
	arpRedirectFlow, err := self.inputTable.NewFlow(ofctrl.FlowMatch{
		Priority:  FLOW_MATCH_PRIORITY + 2,
		Ethertype: 0x0806,
	})

	if err != nil {
		log.Errorf("Error when add local endpoint arp redirect flow")
		return err
	}
	arpRedirectFlow.Next(sw.SendToController())
	self.arpRedirectFlow = arpRedirectFlow

	return nil
}

func (self *VlanArpLearnerBridge) installFromUplinkFlow(ofPort uint32) error {
	// Add uplink port redirect flow: redirect to normalLookupFlow.
	ingressTier0Table := self.ofSwitch.GetTable(INGRESS_TIER0_TBL_ID)
	egressSelectTable := self.ofSwitch.GetTable(EGRESS_SELECT_TBL_ID)

	// Datapath setup with specific uplink port configuration. if uplinkport wasn't configured, sendto normal
	inputFromUplinkIpFlow, err := egressSelectTable.NewFlow(ofctrl.FlowMatch{
		Priority:  FLOW_MATCH_PRIORITY + 1,
		Ethertype: 0x0800,
		InputPort: ofPort,
	})
	if err != nil {
		log.Errorf("Error when create inputTable inputFromUplinkIpFlow. Err: %v", err)
		return err
	}
	inputFromUplinkIp6Flow, err := egressSelectTable.NewFlow(ofctrl.FlowMatch{
		Priority:  FLOW_MATCH_PRIORITY + 1,
		Ethertype: 0x86DD,
		InputPort: ofPort,
	})
	if err != nil {
		log.Errorf("Error when create inputTable inputFromUplinkIp6Flow. Err: %v", err)
		return err
	}

	err = inputFromUplinkIpFlow.Next(ingressTier0Table)
	if err != nil {
		log.Errorf("Error when create inputTable inputFromUplinkIpFlow action. Err: %v", err)
		return err
	}
	err = inputFromUplinkIp6Flow.Next(ingressTier0Table)
	if err != nil {
		log.Errorf("Error when create inputTable inputFromUplinkIp6Flow action. Err: %v", err)
		return err
	}

	self.fromUplinkFlow[ofPort] = []*ofctrl.Flow{inputFromUplinkIpFlow, inputFromUplinkIp6Flow}
	return nil
}

func (self *VlanArpLearnerBridge) installFromLocalIpFlow() error {
	// Send all ip flow except fromUplinkFlow to egressTier0Table
	egressTier0Table := self.ofSwitch.GetTable(EGRESS_TIER0_TBL_ID)
	egressSelectTable := self.ofSwitch.GetTable(EGRESS_SELECT_TBL_ID)

	inputIpFromLocalFlow, err := egressSelectTable.NewFlow(ofctrl.FlowMatch{
		Priority:  FLOW_MATCH_PRIORITY,
		Ethertype: 0x0800,
	})
	if err != nil {
		log.Errorf("Error when create inputTable inputFromLocalIpFlow. Err: %v", err)
		return err
	}
	inputIp6FromLocalFlow, err := egressSelectTable.NewFlow(ofctrl.FlowMatch{
		Priority:  FLOW_MATCH_PRIORITY,
		Ethertype: 0x86DD,
	})
	if err != nil {
		log.Errorf("Error when create inputTable inputFromUplinkIp6Flow. Err: %v", err)
		return err
	}
	err = inputIpFromLocalFlow.Next(egressTier0Table)
	if err != nil {
		log.Errorf("Error when create inputTable inputFromLocalIpFlow action. Err: %v", err)
		return err
	}
	err = inputIp6FromLocalFlow.Next(egressTier0Table)
	if err != nil {
		log.Errorf("Error when create inputTable inputFromLocalIp6Flow action. Err: %v", err)
		return err
	}

	self.fromLocalFlow = []*ofctrl.Flow{inputIpFromLocalFlow, inputIp6FromLocalFlow}

	return nil
}

func (self *VlanArpLearnerBridge) AddUplink(uplinkPort *PortInfo) error {
	var err error
	// Add uplink just add uplink setup configuration to uplinkDb
	curUplinkPortSet := self.getUplinkPort()
	uplinkPortNum := curUplinkPortSet.Cardinality()

	if uplinkPortNum != 0 {
		log.Errorf("%d uplink port already exists.", uplinkPortNum)
		return errors.New("uplinkPort already exists")
	}
	self.installFromLocalIpFlow()

	for _, link := range uplinkPort.MbrLinks {
		err = self.installFromUplinkFlow(link.OfPort)

		if err != nil {
			return err
		}
	}
	// TODO Add uplink status management and GARP func

	self.uplinkPortDb.Set(uplinkPort.Name, uplinkPort)

	return nil
}

func (self *VlanArpLearnerBridge) UpdateUplink(uplinkName string, update PortUpdates) error {
	// TODO. add uplink status management
	return nil
}

func (self *VlanArpLearnerBridge) RemoveUplink(uplinkName string) error {
	uplinkPort := self.GetUplink(uplinkName)
	if uplinkPort == nil {
		err := fmt.Errorf("Could not get uplink with name: %s", uplinkName)
		return err
	}

	// For remove uplink, first remove inputFromLocalIpFlow
	for _, flow := range self.fromLocalFlow {
		flow.Delete()
	}

	for _, link := range uplinkPort.MbrLinks {
		if fromUplinkFlow, ok := self.fromUplinkFlow[link.OfPort]; ok {
			for _, flow := range fromUplinkFlow {
				flow.Delete()
			}
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
	self.nmlTable, _ = sw.NewTable(MAC_DEST_TBL_ID)

	err := self.policyAgent.InitTables(MAC_DEST_TBL_ID)
	if err != nil {
		log.Fatalf("Error when installing Policy table. Err: %v", err)
		return err
	}

	conntrackTable := self.ofSwitch.GetTable(CONNTRACK_TBL_ID)
	inputTableIpFlow, _ := self.inputTable.NewFlow(ofctrl.FlowMatch{
		Priority:  FLOW_MATCH_PRIORITY,
		Ethertype: 0x0800,
	})
	inputTableIpFlow.Next(conntrackTable)

	inputMissFlow, _ := self.inputTable.NewFlow(ofctrl.FlowMatch{
		Priority: FLOW_MISS_PRIORITY,
	})
	inputMissFlow.Next(self.nmlTable)

	self.installArpRedirectFlow()

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
	var isLearning bool = false

	switch t := pkt.Data.(type) {
	case *protocol.ARP:
		var arpIn protocol.ARP = *t

		endpointInfo, ok := self.agent.localEndpointInfo[inPort]
		if !ok {
			log.Infof("local ofport %d related ovsport was't learned or ofPort update", inPort)
			isLearning = true
		} else {
			if !endpointInfo.IpAddr.Equal(arpIn.IPSrc) {
				log.Infof("local ofport %d related endpoint ipaddress update from %v to %v", inPort, endpointInfo.IpAddr, arpIn.IPSrc)
				isLearning = true
			}
		}

		if isLearning {
			self.learnFromArp(arpIn, inPort)
		}
		self.arpNoraml(pkt, inPort)
	}
}

func (self *VlanArpLearnerBridge) learnFromArp(arpIn protocol.ARP, inPort uint32) {
	var ofPortUpdatedPorts, ipAddrUpdatedPorts, deprecatedEndpointOfPorts []uint32

	if self.isLocalInputPort(inPort) {
		ofPortUpdatedPorts, ipAddrUpdatedPorts = self.filterByMacAddr(arpIn, inPort)

		// ArpIn related endpointInfo entry not exists, just add it
		if len(ofPortUpdatedPorts) == 0 && len(ipAddrUpdatedPorts) == 0 {
			log.Infof("Learning localOfPort endpointInfo %d : %v.", inPort, arpIn.IPSrc)
			self.addLocalEndpointInfoEntry(arpIn, inPort)
			self.installIngressSelectFlow(arpIn.HWSrc)
			self.notifyLocalEndpointInfoUpdate(arpIn, inPort, false)
			return
		}

		// ArpIn related endpointInfo entry already exists, Update map[ofport]endpointInfo
		for _, ofPort := range ofPortUpdatedPorts {
			log.Infof("Update localOfPort endpointInfo from %d : %v to %d : %v", ofPort, self.agent.localEndpointInfo[ofPort].IpAddr, inPort, arpIn.IPSrc)
			delete(self.agent.localEndpointInfo, ofPort)
			self.notifyLocalEndpointInfoUpdate(arpIn, ofPort, true)

			self.addLocalEndpointInfoEntry(arpIn, inPort)
			self.notifyLocalEndpointInfoUpdate(arpIn, inPort, false)
		}

		for _, ofPort := range ipAddrUpdatedPorts {
			log.Infof("Update ip address of local endpoint with ofPort %d from %v to %v.", ofPort, self.agent.localEndpointInfo[ofPort].IpAddr, arpIn.IPSrc)
			self.addLocalEndpointInfoEntry(arpIn, inPort)
			self.notifyLocalEndpointInfoUpdate(arpIn, inPort, false)
		}
	} else {
		deprecatedEndpointOfPorts = self.filterByIpAddr(arpIn, inPort)

		// Flush map[ofport]endpointInfo, update local agentmonitor ofPortIpAddressCache
		for _, ofPort := range deprecatedEndpointOfPorts {
			log.Infof("Flush Learned localOfPort endpointInfo %d : %v.", ofPort, arpIn.IPSrc)
			self.uninstallIngressSelectFlow(arpIn.HWSrc)
			delete(self.agent.localEndpointInfo, ofPort)
			self.notifyLocalEndpointInfoUpdate(arpIn, ofPort, true)
		}
	}
}

func (self *VlanArpLearnerBridge) filterByIpAddr(arpIn protocol.ARP, inPort uint32) []uint32 {
	var ports []uint32

	for ofPort, endpointInfo := range self.agent.localEndpointInfo {
		if endpointInfo.IpAddr.Equal(arpIn.IPSrc) && ofPort != inPort {
			ports = append(ports, ofPort)
		}
	}

	return ports
}

func (self *VlanArpLearnerBridge) filterByMacAddr(arpIn protocol.ARP, inPort uint32) ([]uint32, []uint32) {
	var ofPortUpdatedPorts, ipAddrUpdatedPorts []uint32

	for ofPort, endpointInfo := range self.agent.localEndpointInfo {
		if endpointInfo.MacAddr.String() == arpIn.HWSrc.String() && ofPort != inPort {
			ofPortUpdatedPorts = append(ofPortUpdatedPorts, ofPort)
		}
		if endpointInfo.MacAddr.String() == arpIn.HWSrc.String() && ofPort == inPort &&
			!endpointInfo.IpAddr.Equal(arpIn.IPSrc) {
			ipAddrUpdatedPorts = append(ipAddrUpdatedPorts, ofPort)
		}
	}

	return ofPortUpdatedPorts, ipAddrUpdatedPorts
}

func (self *VlanArpLearnerBridge) isLocalInputPort(inPort uint32) bool {
	uplinkOfPortSet := self.getUplinkPort()
	isUplinkPort := uplinkOfPortSet.Contains(inPort)

	return !isUplinkPort
}

func (self *VlanArpLearnerBridge) getUplinkPort() mapset.Set {
	uplinkOfPortSet := mapset.NewSet()

	for uplinkObj := range self.uplinkPortDb.IterBuffered() {
		uplink := uplinkObj.Val.(*PortInfo)
		for _, link := range uplink.MbrLinks {
			uplinkOfPortSet.Add(link.OfPort)
		}
	}

	return uplinkOfPortSet
}

func (self *VlanArpLearnerBridge) notifyLocalEndpointInfoUpdate(arpIn protocol.ARP, ofPort uint32, isDelete bool) {
	updatedOfPortInfo := make(map[uint32][]net.IP)
	if isDelete {
		updatedOfPortInfo[ofPort] = []net.IP{}
	} else {
		updatedOfPortInfo[ofPort] = []net.IP{arpIn.IPSrc}
	}
	self.agent.ofPortIpAddressUpdateChan <- updatedOfPortInfo
}

func (self *VlanArpLearnerBridge) addLocalEndpointInfoEntry(arpIn protocol.ARP, ofPort uint32) {
	learnedIp := make(net.IP, len(arpIn.IPSrc))
	learnedMac := make(net.HardwareAddr, len(arpIn.HWSrc))
	copy(learnedIp, arpIn.IPSrc)
	copy(learnedMac, arpIn.HWSrc)
	endpointInfo := &endpointInfo{
		OfPort:  ofPort,
		IpAddr:  learnedIp,
		MacAddr: learnedMac,
	}
	self.agent.localEndpointInfo[ofPort] = endpointInfo
}

func (self *VlanArpLearnerBridge) installIngressSelectFlow(macDa net.HardwareAddr) error {
	ingressSelectTable := self.ofSwitch.GetTable(INGRESS_SELECT_TBL_ID)
	ingressTier0Table := self.ofSwitch.GetTable(INGRESS_TIER0_TBL_ID)

	ingressSelectFlow, _ := ingressSelectTable.NewFlow(ofctrl.FlowMatch{
		Ethertype: 0x0800,
		MacDa:     &macDa,
	})
	ingressSelectFlow.Next(ingressTier0Table)

	self.ingressSelectFlow[macDa.String()] = ingressSelectFlow
	return nil
}

func (self *VlanArpLearnerBridge) uninstallIngressSelectFlow(macDa net.HardwareAddr) error {
	if flow, ok := self.ingressSelectFlow[macDa.String()]; ok {
		flow.Delete()
		delete(self.ingressSelectFlow, macDa.String())
		return nil
	}
	return errors.New("Can't find ingressSelectFlow for macda")
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

func (self *VlanArpLearnerBridge) GetPolicyAgent() *PolicyAgent {
	return self.policyAgent
}
