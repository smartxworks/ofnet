/***
Copyright 2014 Cisco Systems Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ofnet

import (
	"errors"
	"net"
	"net/rpc"
	"reflect"
	"sync"

	log "github.com/Sirupsen/logrus"
	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/ofnet/ofctrl"
)

// This file has security policy rule implementation

const TCP_FLAG_ACK = 0x10
const TCP_FLAG_SYN = 0x2

var (
	conntrackStateTableId  uint8  = CONNTRACK_STATE_TBL_ID
	conntrackCommitTableId uint8  = MAC_DEST_TBL_ID
	conntrackZone          uint16 = 65535
)

// PolicyRule has info about single rule
type PolicyRule struct {
	Rule *OfnetPolicyRule // rule definition
	flow *ofctrl.Flow     // Flow associated with the flow
}

// PolicyAgent is an instance of a policy agent
type PolicyAgent struct {
	agent                *OfnetAgent      // Pointer back to ofnet agent that owns this
	ofSwitch             *ofctrl.OFSwitch // openflow switch we are talking to
	dstGrpTable          *ofctrl.Table    // dest group lookup table
	policyTable          *ofctrl.Table    // Policy rule lookup table
	nextTable            *ofctrl.Table    // Next table to goto for accepted packets
	conntrackTable       *ofctrl.Table
	conntrackStateTable  *ofctrl.Table
	conntrackCommitTable *ofctrl.Table
	egressSelectTable    *ofctrl.Table
	egressTier0Table     *ofctrl.Table
	egressTier1Table     *ofctrl.Table
	egressTier2Table     *ofctrl.Table
	ingressTier0Table    *ofctrl.Table
	ingressTier1Table    *ofctrl.Table
	ingressTier2Table    *ofctrl.Table
	ingressSelectTable   *ofctrl.Table
	Rules                map[string]*PolicyRule  // rules database
	dstGrpFlow           map[string]*ofctrl.Flow // FLow entries for dst group lookup
	mutex                sync.RWMutex
}

// NewPolicyMgr Creates a new policy manager
func NewPolicyAgent(agent *OfnetAgent, rpcServ *rpc.Server) *PolicyAgent {
	policyAgent := new(PolicyAgent)

	// initialize
	policyAgent.agent = agent
	policyAgent.Rules = make(map[string]*PolicyRule)
	policyAgent.dstGrpFlow = make(map[string]*ofctrl.Flow)

	// Register for Master add/remove events
	if rpcServ != nil {
		rpcServ.Register(policyAgent)
	}

	// done
	return policyAgent
}

// Handle switch connected notification
func (self *PolicyAgent) SwitchConnected(sw *ofctrl.OFSwitch) {
	// Keep a reference to the switch
	self.ofSwitch = sw

	log.Infof("Switch connected(policyAgent).")
}

// Handle switch disconnected notification
func (self *PolicyAgent) SwitchDisconnected(sw *ofctrl.OFSwitch) {
	// FIXME: ??
}

// ruleIsSame check if two rules are identical
func ruleIsSame(r1, r2 *OfnetPolicyRule) bool {
	return reflect.DeepEqual(*r1, *r2)
}

func (self *PolicyAgent) AddEndpoint(endpoint *OfnetEndpoint) error {
	return nil
}

func (self *PolicyAgent) DelEndpoint(endpoint *OfnetEndpoint) error {
	return nil
}

func (self *PolicyAgent) AddIpv6Endpoint(endpoint *OfnetEndpoint) error {
	return nil
}

func (self *PolicyAgent) DelIpv6Endpoint(endpoint *OfnetEndpoint) error {
	return nil
}

func (self *PolicyAgent) GetTierTable(direction uint8, tier uint8) (*ofctrl.Table, *ofctrl.Table, error) {
	var policyTable, nextTable *ofctrl.Table
	switch direction {
	case POLICY_DIRECTION_OUT:
		switch tier {
		case POLICY_TIER0:
			policyTable = self.egressTier0Table
			nextTable = self.egressTier1Table
		case POLICY_TIER1:
			policyTable = self.egressTier1Table
			nextTable = self.egressTier2Table
		case POLICY_TIER2:
			policyTable = self.egressTier2Table
			nextTable = self.ingressSelectTable
		default:
			return nil, nil, errors.New("unknow policy tier")
		}
	case POLICY_DIRECTION_IN:
		switch tier {
		case POLICY_TIER0:
			policyTable = self.ingressTier0Table
			nextTable = self.ingressTier1Table
		case POLICY_TIER1:
			policyTable = self.ingressTier1Table
			nextTable = self.ingressTier2Table
		case POLICY_TIER2:
			policyTable = self.ingressTier2Table
			nextTable = self.conntrackCommitTable
		default:
			return nil, nil, errors.New("unknow policy tier")
		}
	}

	return policyTable, nextTable, nil
}

func (self *PolicyAgent) AddRuleToTier(rule *OfnetPolicyRule, direction uint8, tier uint8) error {
	var ipDa *net.IP = nil
	var ipDaMask *net.IP = nil
	var ipSa *net.IP = nil
	var ipSaMask *net.IP = nil
	var flag, flagMask uint16
	var flagPtr, flagMaskPtr *uint16
	var err error

	// make sure switch is connected
	if !self.agent.IsSwitchConnected() {
		self.agent.WaitForSwitchConnection()
	}

	// Different tier have different nextTable select strategy:
	policyTable, nextTable, e := self.GetTierTable(direction, tier)
	if e != nil {
		log.Errorf("error when get policy table tier %v", tier)
		return errors.New("failed get policy table")
	}

	// check if we already have the rule
	self.mutex.RLock()
	if _, ok := self.Rules[rule.RuleId]; ok {
		oldRule := self.Rules[rule.RuleId].Rule

		if ruleIsSame(oldRule, rule) {
			self.mutex.RUnlock()
			log.Infof("Rule already exists. new rule: {%+v}, old rule: {%+v}", rule, oldRule)
			return nil
		} else {
			self.mutex.RUnlock()
			log.Fatalf("Different rule %v and %v with same ruleId.", oldRule, rule)
			return nil
		}
	}
	self.mutex.RUnlock()

	log.Infof("Received AddRule: %+v", rule)

	// Parse dst ip
	if rule.DstIpAddr != "" {
		ipDa, ipDaMask, err = ParseIPAddrMaskString(rule.DstIpAddr)
		if err != nil {
			log.Errorf("Error parsing dst ip %s. Err: %v", rule.DstIpAddr, err)
			return err
		}
	}

	// parse src ip
	if rule.SrcIpAddr != "" {
		ipSa, ipSaMask, err = ParseIPAddrMaskString(rule.SrcIpAddr)
		if err != nil {
			log.Errorf("Error parsing src ip %s. Err: %v", rule.SrcIpAddr, err)
			return err
		}
	}

	// Setup TCP flags
	if rule.IpProtocol == 6 && rule.TcpFlags != "" {
		switch rule.TcpFlags {
		case "syn":
			flag = TCP_FLAG_SYN
			flagMask = TCP_FLAG_SYN
		case "syn,ack":
			flag = TCP_FLAG_ACK | TCP_FLAG_SYN
			flagMask = TCP_FLAG_ACK | TCP_FLAG_SYN
		case "ack":
			flag = TCP_FLAG_ACK
			flagMask = TCP_FLAG_ACK
		case "syn,!ack":
			flag = TCP_FLAG_SYN
			flagMask = TCP_FLAG_ACK | TCP_FLAG_SYN
		case "!syn,ack":
			flag = TCP_FLAG_ACK
			flagMask = TCP_FLAG_ACK | TCP_FLAG_SYN
		default:
			log.Errorf("Unknown TCP flags: %s, in rule: %+v", rule.TcpFlags, rule)
			return errors.New("Unknown TCP flag")
		}

		flagPtr = &flag
		flagMaskPtr = &flagMask
	}
	// Install the rule in policy table
	ruleFlow, err := policyTable.NewFlow(ofctrl.FlowMatch{
		Priority:     uint16(FLOW_POLICY_PRIORITY_OFFSET + rule.Priority),
		Ethertype:    0x0800,
		IpDa:         ipDa,
		IpDaMask:     ipDaMask,
		IpSa:         ipSa,
		IpSaMask:     ipSaMask,
		IpProto:      rule.IpProtocol,
		TcpSrcPort:   rule.SrcPort,
		TcpDstPort:   rule.DstPort,
		UdpSrcPort:   rule.SrcPort,
		UdpDstPort:   rule.DstPort,
		TcpFlags:     flagPtr,
		TcpFlagsMask: flagMaskPtr,
	})
	if err != nil {
		log.Errorf("Error adding flow for rule {%v}. Err: %v", rule, err)
		return err
	}

	// Point it to next table
	if rule.Action == "passthrough" {
		err = ruleFlow.Next(self.conntrackCommitTable)
		if err != nil {
			log.Errorf("Error installing flow {%+v}. Err: %v", ruleFlow, err)
			return err
		}
	} else if rule.Action == "allow" {
		err = ruleFlow.Next(nextTable)
		if err != nil {
			log.Errorf("Error installing flow {%+v}. Err: %v", ruleFlow, err)
			return err
		}
	} else if rule.Action == "deny" {
		err = ruleFlow.Next(self.ofSwitch.DropAction())
		if err != nil {
			log.Errorf("Error installing flow {%+v}. Err: %v", ruleFlow, err)
			return err
		}
	} else {
		log.Errorf("Unknown action in rule {%+v}", rule)
		return errors.New("Unknown action in rule")
	}

	// save the rule
	pRule := PolicyRule{
		Rule: rule,
		flow: ruleFlow,
	}
	self.mutex.Lock()
	self.Rules[rule.RuleId] = &pRule
	self.mutex.Unlock()

	return nil
}

// AddRule adds a security rule to policy table
func (self *PolicyAgent) AddRule(rule *OfnetPolicyRule, ret *bool) error {
	return self.AddRuleToTier(rule, POLICY_DIRECTION_OUT, POLICY_TIER0)
}

// DelRule deletes a security rule from policy table
func (self *PolicyAgent) DelRule(rule *OfnetPolicyRule, ret *bool) error {
	log.Infof("Received DelRule: %+v", rule)

	// Gte the rule
	self.mutex.Lock()
	defer self.mutex.Unlock()
	cache := self.Rules[rule.RuleId]
	if cache == nil {
		log.Infof("Rule not found when deleting %+v", rule)
		return nil
	}

	// Delete the Flow
	err := cache.flow.Delete()
	if err != nil {
		log.Errorf("Error deleting flow: %+v. Err: %v", rule, err)
		return err
	}

	// Delete the rule from cache
	delete(self.Rules, rule.RuleId)

	return nil
}

// InitTables initializes policy table on the switch
func (self *PolicyAgent) InitTables(nextTblId uint8) error {
	sw := self.ofSwitch

	nextTbl := sw.GetTable(nextTblId)
	if nextTbl == nil {
		log.Fatalf("Error getting table id: %d", nextTblId)
	}

	self.nextTable = nextTbl

	// Create all tables
	self.conntrackTable, _ = sw.NewTable(CONNTRACK_TBL_ID)
	self.conntrackStateTable, _ = sw.NewTable(CONNTRACK_STATE_TBL_ID)
	self.conntrackCommitTable, _ = sw.NewTable(CONNTRACK_COMMIT_TBL_ID)
	self.egressTier0Table, _ = sw.NewTable(EGRESS_TIER0_TBL_ID)
	self.egressTier1Table, _ = sw.NewTable(EGRESS_TIER1_TBL_ID)
	self.egressTier2Table, _ = sw.NewTable(EGRESS_TIER2_TBL_ID)
	self.ingressTier0Table, _ = sw.NewTable(INGRESS_TIER0_TBL_ID)
	self.ingressTier1Table, _ = sw.NewTable(INGRESS_TIER1_TBL_ID)
	self.ingressTier2Table, _ = sw.NewTable(INGRESS_TIER2_TBL_ID)

	self.ingressSelectTable, _ = sw.NewTable(INGRESS_SELECT_TBL_ID)
	self.egressSelectTable, _ = sw.NewTable(EGRESS_SELECT_TBL_ID)

	// Init default flow
	// Conntrack Flow
	ctAction := ofctrl.NewConntrackAction(false, false, &conntrackStateTableId, &conntrackZone)
	conntrackTableDefaultFlow, _ := self.conntrackTable.NewFlow(ofctrl.FlowMatch{
		Priority:  FLOW_MATCH_PRIORITY,
		Ethertype: 0x0800,
	})
	conntrackTableDefaultFlow.SetConntrack(ctAction)

	// ConntrackState flow
	ctTrkState := openflow13.NewCTStates()
	ctTrkState.UnsetNew()
	ctTrkState.SetTrk()
	conntrackStateTableTrackedFlow, _ := self.conntrackStateTable.NewFlow(ofctrl.FlowMatch{
		Priority: FLOW_MATCH_PRIORITY + 2,
		CtStates: ctTrkState,
	})
	conntrackStateTableTrackedFlow.Next(self.egressSelectTable)

	ctInvState := openflow13.NewCTStates()
	ctInvState.SetInv()
	ctInvState.SetTrk()
	conntrackStateTableInvlidFlow, _ := self.conntrackStateTable.NewFlow(ofctrl.FlowMatch{
		Priority: FLOW_MATCH_PRIORITY + 1,
		CtStates: ctInvState,
	})
	conntrackStateTableInvlidFlow.Next(self.ofSwitch.DropAction())

	conntrackStateTableDefaultFlow, _ := self.conntrackStateTable.NewFlow(ofctrl.FlowMatch{
		Priority: FLOW_MISS_PRIORITY,
	})
	conntrackStateTableDefaultFlow.Next(self.egressSelectTable)

	// Egress select table implement to uplink ip flow redirect in high priority, defalult flow redirect all missed flow
	// to egressTier0Table
	ctEstState := openflow13.NewCTStates()
	ctEstState.UnsetNew()
	ctEstState.SetEst()
	egressSelectTableConnEstFlow, _ := self.egressSelectTable.NewFlow(ofctrl.FlowMatch{
		Priority:  FLOW_MATCH_PRIORITY + 2,
		Ethertype: 0x0800,
		CtStates:  ctEstState,
	})
	egressSelectTableConnEstFlow.Next(self.conntrackCommitTable)

	egressSelectTableDefaultFlow, _ := self.egressSelectTable.NewFlow(ofctrl.FlowMatch{
		Priority: FLOW_MISS_PRIORITY,
	})
	egressSelectTableDefaultFlow.Next(self.egressTier0Table)

	egressTier0TableDefaultFlow, _ := self.egressTier0Table.NewFlow(ofctrl.FlowMatch{
		Priority: FLOW_MISS_PRIORITY,
	})
	egressTier0TableDefaultFlow.Next(self.egressTier1Table)

	egressTier1TableDefaultFlow, _ := self.egressTier1Table.NewFlow(ofctrl.FlowMatch{
		Priority: FLOW_MISS_PRIORITY,
	})
	egressTier1TableDefaultFlow.Next(self.egressTier2Table)

	egressTier2TableDefaultFlow, _ := self.egressTier2Table.NewFlow(ofctrl.FlowMatch{
		Priority: FLOW_MISS_PRIORITY,
	})
	egressTier2TableDefaultFlow.Next(self.ingressSelectTable)

	// Ingress select table implement to local endpoint flow redirect, defalult flow redirect all missed flow to conntrackCommitTable
	ingressSelectTableCtEstFlow, _ := self.ingressSelectTable.NewFlow(ofctrl.FlowMatch{
		Priority: FLOW_MATCH_PRIORITY + 2,
		CtStates: ctEstState,
	})
	ingressSelectTableCtEstFlow.Next(self.conntrackCommitTable)

	ingressSelectTableDefaultFlow, _ := self.ingressSelectTable.NewFlow(ofctrl.FlowMatch{
		Priority: FLOW_MISS_PRIORITY,
	})
	ingressSelectTableDefaultFlow.Next(self.conntrackCommitTable)

	ingressTier0TableDefaultFlow, _ := self.ingressTier0Table.NewFlow(ofctrl.FlowMatch{
		Priority: FLOW_MISS_PRIORITY,
	})
	ingressTier0TableDefaultFlow.Next(self.ingressTier1Table)

	ingressTier1TableDefaultFlow, _ := self.ingressTier1Table.NewFlow(ofctrl.FlowMatch{
		Priority: FLOW_MISS_PRIORITY,
	})
	ingressTier1TableDefaultFlow.Next(self.ingressTier2Table)

	ingressTier2TableDefaultFlow, _ := self.ingressTier2Table.NewFlow(ofctrl.FlowMatch{
		Priority: FLOW_MISS_PRIORITY,
	})
	ingressTier2TableDefaultFlow.Next(self.conntrackCommitTable)

	// ConntrackCommit table
	ctCommitAction := ofctrl.NewConntrackAction(true, false, &conntrackCommitTableId, &conntrackZone)
	ctTrkedState := openflow13.NewCTStates()
	ctTrkedState.SetNew()
	ctTrkedState.SetTrk()
	conntrackCommitTableCommitFlow, _ := self.conntrackCommitTable.NewFlow(ofctrl.FlowMatch{
		Priority:  FLOW_MATCH_PRIORITY,
		Ethertype: 0x0800,
		CtStates:  ctTrkedState,
	})
	conntrackCommitTableCommitFlow.SetConntrack(ctCommitAction)

	conntrackCommitTableDefaultFlow, _ := self.conntrackCommitTable.NewFlow(ofctrl.FlowMatch{
		Priority: FLOW_MISS_PRIORITY,
	})
	conntrackCommitTableDefaultFlow.Next(self.nextTable)

	return nil
}
