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
	"fmt"
	"net"
	"testing"

	log "github.com/Sirupsen/logrus"
	"github.com/contiv/ofnet/ovsdbDriver"
)

func TestPolicyAddDelete(t *testing.T) {
	var resp bool
	rpcPort := uint16(9600)
	ovsPort := uint16(9601)
	lclIP := net.ParseIP("10.10.10.10")
	ofnetAgent, err := NewOfnetAgent("", "vrouter", lclIP, rpcPort, ovsPort, nil)
	if err != nil {
		t.Fatalf("Error creating ofnet agent. Err: %v", err)
	}

	defer func() { ofnetAgent.Delete() }()

	// Override MyAddr to local host
	ofnetAgent.MyAddr = "127.0.0.1"

	// Create a Master
	ofnetMaster := NewOfnetMaster("", uint16(9602))

	defer func() { ofnetMaster.Delete() }()

	masterInfo := OfnetNode{
		HostAddr: "127.0.0.1",
		HostPort: uint16(9602),
	}

	// connect vrtr agent to master
	err = ofnetAgent.AddMaster(&masterInfo, &resp)
	if err != nil {
		t.Errorf("Error adding master %+v. Err: %v", masterInfo, err)
	}

	log.Infof("Created vrouter ofnet agent: %v", ofnetAgent)

	brName := "ovsbr60"
	ovsDriver := ovsdbDriver.NewOvsDriver(brName)
	err = ovsDriver.AddController("127.0.0.1", ovsPort)
	if err != nil {
		t.Fatalf("Error adding controller to ovs: %s", brName)
	}

	// Wait for switch to connect to controller
	ofnetAgent.WaitForSwitchConnection()

	// Create a vlan for the endpoint
	ofnetAgent.AddNetwork(1, 1, "", "default")

	macAddr, _ := net.ParseMAC("00:01:02:03:04:05")
	endpoint := EndpointInfo{
		PortNo:  12,
		MacAddr: macAddr,
		Vlan:    1,
		IpAddr:  net.ParseIP("10.2.2.2"),
	}

	log.Infof("Adding Local endpoint: %+v", endpoint)

	// Add an Endpoint
	err = ofnetAgent.AddLocalEndpoint(endpoint)
	if err != nil {
		t.Errorf("Error adding endpoint. Err: %v", err)
		return
	}

	tcpRule := &OfnetPolicyRule{
		RuleId:     "tcpRule",
		Priority:   100,
		SrcIpAddr:  "10.10.10.0/24",
		DstIpAddr:  "10.1.1.0/24",
		IpProtocol: 6,
		DstPort:    100,
		SrcPort:    200,
		Action:     "allow",
	}

	log.Infof("Adding rule: %+v", tcpRule)

	// Add a policy
	err = ofnetMaster.AddRule(tcpRule)
	if err != nil {
		t.Errorf("Error installing tcpRule {%+v}. Err: %v", tcpRule, err)
		return
	}

	udpRule := &OfnetPolicyRule{
		RuleId:     "udpRule",
		Priority:   100,
		SrcIpAddr:  "20.20.20.0/24",
		DstIpAddr:  "20.2.2.0/24",
		IpProtocol: 17,
		DstPort:    300,
		SrcPort:    400,
		Action:     "deny",
	}

	log.Infof("Adding rule: %+v", udpRule)

	// Add the policy
	err = ofnetMaster.AddRule(udpRule)
	if err != nil {
		t.Errorf("Error installing udpRule {%+v}. Err: %v", udpRule, err)
		return
	}

	// Get all the flows
	flowList, err := ofctlFlowDump(brName)
	if err != nil {
		t.Errorf("Error getting flow entries. Err: %v", err)
		return
	}
	// verify tcp rule flow entry exists
	tcpFlowMatch := fmt.Sprintf("priority=110,tcp,nw_src=10.10.10.0/24,nw_dst=10.1.1.0/24,tp_src=200,tp_dst=100")
	if !ofctlFlowMatch(flowList, POLICY_TBL_ID, tcpFlowMatch) {
		t.Fatalf("Could not find the flow %s on ovs %s", tcpFlowMatch, brName)
	}

	log.Infof("Found tcp rule %s on ovs %s", tcpFlowMatch, brName)

	// verify udp rule flow
	udpFlowMatch := fmt.Sprintf("priority=110,udp,nw_src=20.20.20.0/24,nw_dst=20.2.2.0/24,tp_src=400,tp_dst=300")
	if !ofctlFlowMatch(flowList, POLICY_TBL_ID, udpFlowMatch) {
		t.Fatalf("Could not find the flow %s on ovs %s", udpFlowMatch, brName)
	}

	log.Infof("Found udp rule %s on ovs %s", udpFlowMatch, brName)

	// Delete policies
	err = ofnetMaster.DelRule(tcpRule)
	if err != nil {
		t.Fatalf("Error deleting tcpRule {%+v}. Err: %v", tcpRule, err)
	}
	err = ofnetMaster.DelRule(udpRule)
	if err != nil {
		t.Fatalf("Error deleting udpRule {%+v}. Err: %v", udpRule, err)
	}
	err = ofnetAgent.RemoveLocalEndpoint(endpoint.PortNo)
	if err != nil {
		t.Fatalf("Error deleting endpoint: %+v. Err: %v", endpoint, err)
	}

	log.Infof("Deleted all policy entries")

	// Get the flows again
	flowList, err = ofctlFlowDump(brName)
	if err != nil {
		t.Fatalf("Error getting flow entries. Err: %v", err)
	}

	if ofctlFlowMatch(flowList, POLICY_TBL_ID, tcpFlowMatch) {
		t.Fatalf("Still found the flow %s on ovs %s", tcpFlowMatch, brName)
	}
	if ofctlFlowMatch(flowList, POLICY_TBL_ID, udpFlowMatch) {
		t.Fatalf("Still found the flow %s on ovs %s", udpFlowMatch, brName)
	}

	log.Infof("Verified all flows are deleted")
}
