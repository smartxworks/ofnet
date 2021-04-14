package ofnet

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/libOpenflow/protocol"
	"github.com/deckarep/golang-set"
	cmap "github.com/streamrail/concurrent-map"

	"github.com/contiv/ofnet/ofctrl"
	"github.com/contiv/ofnet/ofctrl/cookie"
)

type VlanArpLearnerBridge struct {
	agent    *OfnetAgent
	ofSwitch *ofctrl.OFSwitch

	inputTable             *ofctrl.Table
	ingressSelectTable     *ofctrl.Table
	nmlTable               *ofctrl.Table
	arpRedirectFlow        *ofctrl.Flow
	fromUplinkFlowMutex    sync.RWMutex
	fromUplinkFlow         map[uint32][]*ofctrl.Flow
	fromLocalFlow          []*ofctrl.Flow
	ingressSelectFlowMutex sync.RWMutex
	ingressSelectFlow      map[string]*ofctrl.Flow
	uplinkPortDb           cmap.ConcurrentMap

	policyAgent  *PolicyAgent
	garpMutex    *sync.Mutex
	epMap        map[string]GARPInfo
	garpBGActive bool
}

func NewVlanArpLearnerBridge(agent *OfnetAgent) *VlanArpLearnerBridge {
	vlanArpLearner := new(VlanArpLearnerBridge)
	vlanArpLearner.agent = agent
	vlanArpLearner.fromUplinkFlow = make(map[uint32][]*ofctrl.Flow)
	vlanArpLearner.ingressSelectFlow = make(map[string]*ofctrl.Flow)
	vlanArpLearner.uplinkPortDb = cmap.New()
	vlanArpLearner.policyAgent = NewPolicyAgent(agent, nil)
	vlanArpLearner.epMap = make(map[string]GARPInfo)
	vlanArpLearner.garpMutex = &sync.Mutex{}
	vlanArpLearner.garpBGActive = false

	return vlanArpLearner
}

func (self *VlanArpLearnerBridge) installFromUplinkFlow(ofPort uint32) error {
	// Arp form uplink: normal
	fromUplinkArpDirectFlow, err := self.inputTable.NewFlow(ofctrl.FlowMatch{
		Priority:  FLOW_MATCH_PRIORITY + 3,
		Ethertype: 0x0806,
		InputPort: ofPort,
	})
	if err != nil {
		log.Fatalf("Failed to create fromUplinkArpDirectFlow: %+v", err)
	}
	fromUplinkArpDirectFlow.Next(self.nmlTable)

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

	self.fromUplinkFlow[ofPort] = []*ofctrl.Flow{inputFromUplinkIpFlow, inputFromUplinkIp6Flow, fromUplinkArpDirectFlow}
	return nil
}

func (self *VlanArpLearnerBridge) installFromLocalFlow() error {
	// Arp from localendpoint: redirect to controller
	fromLocalEndpointArpFlow, err := self.inputTable.NewFlow(ofctrl.FlowMatch{
		Priority:  FLOW_MATCH_PRIORITY + 2,
		Ethertype: 0x0806,
	})
	if err != nil {
		log.Fatalf("Failed to create fromLocalEndpointArpFlow: %+v", err)
	}
	fromLocalEndpointArpFlow.Next(self.ofSwitch.SendToController())

	self.fromLocalFlow = []*ofctrl.Flow{fromLocalEndpointArpFlow}

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

	self.fromUplinkFlowMutex.Lock()
	defer self.fromUplinkFlowMutex.Unlock()

	for _, link := range uplinkPort.MbrLinks {
		err = self.installFromUplinkFlow(link.OfPort)

		if err != nil {
			return err
		}
	}

	err = self.installFromLocalFlow()
	if err != nil {
		return err
	}

	// TODO Add uplink status management and GARP func

	self.uplinkPortDb.Set(uplinkPort.Name, uplinkPort)

	return nil
}

func (self *VlanArpLearnerBridge) UpdateUplink(uplinkName string, update PortUpdates) error {
	for _, portUpdate := range update.Updates {
		switch portUpdate.UpdateType {
		case BondActiveSlaveSwitch:
			curActiveSlaveOfPort := portUpdate.UpdateInfo.(LinkUpdateInfo).ActiveSlaveOfPort
			self.sendGARPAll(curActiveSlaveOfPort)
		default:
			log.Errorf("Unknow update: %+v", portUpdate)
		}
	}

	return nil
}

func (self *VlanArpLearnerBridge) sendGARPAll(curActiveSlaveOfPort uint32) {
	self.garpMutex.Lock()
	defer self.garpMutex.Unlock()

	count := 0
	for ofPort, ep := range self.epMap {
		ep.garpCount = GARPRepeats
		self.epMap[ofPort] = ep
		count++
	}

	if !self.garpBGActive && count > 0 {
		log.Infof("GARPs will be sent for %d eps", count)
		go self.backGroundGARPs(curActiveSlaveOfPort)
		self.garpBGActive = true
	}
}

func (self *VlanArpLearnerBridge) backGroundGARPs(activeSlaveOfport uint32) {
	for {
		self.garpMutex.Lock()

		workDone := false
		for endpointID, ep := range self.epMap {
			if ep.garpCount <= 0 {
				continue
			}

			ep.garpCount--

			err := self.sendGARP(activeSlaveOfport, ep.ip, ep.mac, ep.vlan)
			if err == nil {
				self.agent.incrStats("GARPSent")
			} else {
				log.Warnf("Send GARP failed for ep IP: %v", ep.ip)
			}

			self.epMap[endpointID] = ep

			workDone = true
		}

		if !workDone { // No ep pending. Time to exit
			self.garpBGActive = false
			self.garpMutex.Unlock()
			return
		}

		self.garpMutex.Unlock()
		time.Sleep(GARPDELAY * time.Second)
	}
}

func (self *VlanArpLearnerBridge) sendGARP(ofPort uint32, ip net.IP, mac net.HardwareAddr, vlanID uint16) error {
	pktOut := BuildGarpPkt(ip, mac, vlanID)
	pktOut.AddAction(openflow13.NewActionOutput(ofPort))

	// Send it out
	if self.ofSwitch != nil {
		self.ofSwitch.Send(pktOut)
		self.agent.incrStats("GarpPktSent")
	}

	return nil
}

func (self *VlanArpLearnerBridge) RemoveUplink(uplinkName string) error {
	self.fromUplinkFlowMutex.Lock()
	defer self.fromUplinkFlowMutex.Unlock()

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

	normalLookupFlow, _ := self.nmlTable.NewFlow(ofctrl.FlowMatch{
		Priority: FLOW_MISS_PRIORITY,
	})
	normalLookupFlow.Next(sw.NormalLookup())

	return nil
}

// Controller appinterface: SwitchConnected, SwichDisConnected, MultipartReply, PacketRcvd
func (self *VlanArpLearnerBridge) SwitchConnected(sw *ofctrl.OFSwitch) {
	self.ofSwitch = sw

	roundInfo, err := getRoundInfo(self.agent.ovsDriver)
	if err != nil {
		log.Fatalf("Failed to get Roundinfo from ovsdb: %v", err)
	}

	// Delete flow with curRoundNum cookie, for case: failed when restart process flow install.
	self.ofSwitch.DeleteFlowByRoundInfo(roundInfo.curRoundNum)
	cookieAllocator := cookie.NewAllocator(roundInfo.curRoundNum)
	self.ofSwitch.CookieAllocator = cookieAllocator

	self.policyAgent.SwitchConnected(sw)
	self.initFgraph()

	// Delete flow with previousRoundNum cookie, and then persistent curRoundNum to ovsdb. We need to wait for long
	// enough to guarantee that all of the basic flow which we are still required updated with new roundInfo encoding to
	// flow cookie fields. But the time required to update all of the basic flow with updated roundInfo is
	// non-determined.
	// TODO  Implement a deterministic mechanism to control outdated flow flush procedure
	go func() {
		time.Sleep(time.Second * 15)
		self.ofSwitch.DeleteFlowByRoundInfo(roundInfo.previousRoundNum)
		err = persistentRoundInfo(roundInfo.curRoundNum, self.agent.ovsDriver)
		if err != nil {
			log.Fatalf("Failed to persistent roundInfo into ovsdb: %v", err)
		}
	}()
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
	switch t := pkt.Data.(type) {
	case *protocol.ARP:
		var arpIn protocol.ARP = *t

		for endpointObj := range self.agent.localEndpointDb.IterBuffered() {
			endpoint := endpointObj.Val.(*OfnetEndpoint)

			if endpoint.MacAddrStr == arpIn.HWSrc.String() && endpoint.PortNo != inPort {
				log.Infof("Update localOfPort endpointInfo from %d : %v to %d : %v", endpoint.PortNo,
					endpoint.IpAddr, inPort, arpIn.IPSrc)

				// Clean localEndpoint entry of old ofPort.
				self.agent.localEndpointDb.Remove(fmt.Sprint(endpoint.PortNo))
				self.notifyLocalEndpointInfoUpdate(arpIn, endpoint.PortNo, true)

				learnedIp := make(net.IP, len(arpIn.IPSrc))
				copy(learnedIp, arpIn.IPSrc)
				ofnetEndpoint := &OfnetEndpoint{
					IpAddr:     learnedIp,
					MacAddrStr: endpoint.MacAddrStr,
					PortNo:     inPort,
				}

				self.agent.localEndpointDb.Set(fmt.Sprint(inPort), ofnetEndpoint)
				self.notifyLocalEndpointInfoUpdate(arpIn, inPort, false)
			}

			if endpoint.MacAddrStr == arpIn.HWSrc.String() && endpoint.PortNo == inPort &&
				!endpoint.IpAddr.Equal(arpIn.IPSrc) {
				log.Infof("Update ip address of local endpoint with ofPort %d from %v to %v.", inPort,
					endpoint.IpAddr, arpIn.IPSrc)

				learnedIp := make(net.IP, len(arpIn.IPSrc))
				copy(learnedIp, arpIn.IPSrc)

				ofnetEndpoint := &OfnetEndpoint{
					IpAddr:     learnedIp,
					MacAddrStr: endpoint.MacAddrStr,
					PortNo:     inPort,
				}

				self.agent.localEndpointDb.Set(fmt.Sprint(inPort), ofnetEndpoint)
				self.notifyLocalEndpointInfoUpdate(arpIn, inPort, false)
			}
		}

		// Don't add endpoint from received arp pkt event. We just add local endpoint from control-plane
		// Already exists endpoint, just send out normally

		self.arpNoraml(pkt, inPort)
	}
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

func (self *VlanArpLearnerBridge) installIngressSelectFlow(macDa net.HardwareAddr) error {
	self.ingressSelectFlowMutex.Lock()
	defer self.ingressSelectFlowMutex.Unlock()

	ingressSelectTable := self.ofSwitch.GetTable(INGRESS_SELECT_TBL_ID)
	ingressTier0Table := self.ofSwitch.GetTable(INGRESS_TIER0_TBL_ID)

	ingressSelectFlow, _ := ingressSelectTable.NewFlow(ofctrl.FlowMatch{
		Priority:  FLOW_MATCH_PRIORITY,
		Ethertype: 0x0800,
		MacDa:     &macDa,
	})
	ingressSelectFlow.Next(ingressTier0Table)

	self.ingressSelectFlow[macDa.String()] = ingressSelectFlow
	return nil
}

func (self *VlanArpLearnerBridge) uninstallIngressSelectFlow(macDa net.HardwareAddr) error {
	self.ingressSelectFlowMutex.Lock()
	defer self.ingressSelectFlowMutex.Unlock()

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
	dstMac, err := net.ParseMAC(endpoint.MacAddrStr)
	if err != nil {
		log.Fatalf("Bad format: %+v; parsing local endpoint MacAddr error: %+v", endpoint.MacAddrStr, err)
	}

	// update epDB
	if endpoint.EndpointVlan != 0 {
		self.garpMutex.Lock()

		ep := GARPInfo{
			garpCount: GARPRepeats,
			mac:       dstMac,
			vlan:      endpoint.EndpointVlan,
		}
		self.epMap[fmt.Sprintf("%+8d", endpoint.PortNo)] = ep

		self.garpMutex.Unlock()
	}

	return self.installIngressSelectFlow(dstMac)
}

func (self *VlanArpLearnerBridge) RemoveLocalEndpoint(endpoint OfnetEndpoint) error {
	dstMac, err := net.ParseMAC(endpoint.MacAddrStr)
	if err != nil {
		log.Fatalf("Bad format: %+v; parsing local endpoint MacAddr error: %+v", endpoint.MacAddrStr, err)
	}

	// Remove from ep DB
	self.garpMutex.Lock()
	delete(self.epMap, fmt.Sprintf("%+8d", endpoint.PortNo))
	self.garpMutex.Unlock()

	return self.uninstallIngressSelectFlow(dstMac)
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
