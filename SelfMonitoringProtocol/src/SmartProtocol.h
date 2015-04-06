//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
// 

#ifndef SMARTPROTOCOL_H_
#define SMARTPROTOCOL_H_
#include "INETDefs.h"
#include "PingPayload_m.h"
#include "IPvXAddress.h"
#include "ILifecycle.h"
#include "NodeStatus.h"

#include <queue>
#include "TimeoutMsg_m.h"


namespace selfmonitoringprotocol {

enum connection_status {
    Unknown,
    Discovered,             // node is in range and ready to partner
    Partners,               // nodes are partners
    Fully_engaged           // node is in range but already exceeds max number of partners
};

enum communication_state {
    Wait_state,
    Ping_pong_state,
    Request_partner_state,
    Handle_partner_request_state,
    Close_connection_state
};

enum message_code {
    Probe_ping_msg,               // discover neighbours and get status information
    Probe_pong_msg,               // node status information message
    Probe_timeout_msg,            // neighbour is no longer available / doesn't respond

    Partner_hello_msg,            // start partner request (start handshake)
    Partner_agree_msg,            // positive reply to partnership request
    Partner_decline_msg,          // decline partnership (aborts handshake)
    Partner_confirm_msg,          // confirm partnership with node (finish handshake)
    Partner_agree_timeout_msg,    // timeout for the partnership agree/decline reply
    Partner_confirm_timeout_msg,  // timeout for the partnership confirmation which completes the handshake

    Close_notification_msg,       // notify about ending partnership
    Close_accept_msg,             // accept end of partnership
    Close_denial_msg,             // deny close of connection
    Close_accept_timeout_msg,      // timeout for accepting/denying closing connection

    Alive_msg,                     //Notify partners of your health
    Partner_alive_timeout_msg,      //timeout for a partner alive message,if it fires then partner is probably dead
    Node_update_msg,
    Report_partner_status_msg
};

enum node_status{
    Running,
    Suspect,
    Dead
};

struct partner_item{
    unsigned int partnerId;
    bool reportsAsDead;
};

//Used to store info about a meter at the MCU
struct node_info{
    int nodeId;
    IPv4Address ipAddress;
    std::string nodeName;
    node_status status;
    std::vector<partner_item*> partners;
};

struct neighbour_info {
    IPv4Address ipAddress;           // the neighbours IP address
    std::string nodeName;
    communication_state com_state;   // indicates in which sub-protocol the nodes are
    connection_status con_status;    // the handshake status, e.g., are they partners or do they just know of their presence
    TimeoutMsg *timeout_event;       // pointer to a scheduled timeout event
    TimeoutMsg *is_alive_timeout;
};

struct partner_request_item {
    IPv4Address ipAddress;          // requesting module
    std::set<int> requested_set;    // set of modules already requested before
};

class  SmartProtocol: public cSimpleModule, public ILifecycle
{
public:
    SmartProtocol();
    virtual ~SmartProtocol();
    virtual bool handleOperationStage(LifecycleOperation *operation, int stage, IDoneCallback *doneCallback);

protected:
    virtual void initialize(int stage);
    virtual int numInitStages() const { return 4; }
    virtual void handleMessage(cMessage *msg);
    virtual void finish();


protected:
    virtual void heartbeat();
    virtual void processReceivedMessage(PingPayload*);
    virtual void startRunning();
    virtual void stopRunning();
    virtual void sendMessage(PingPayload *msg,IPv4Address destAddr);
    virtual void sendMessage(PingPayload *msg, const char* destAddrString);

protected:

    IPvXAddress destAddr;
    IPvXAddress srcAddr;
    long sendSeqNo;
    int pid;
    int packetSize;
    bool sendToMCU;
    bool isMCU;

private:
    int node_com_state;                                       // own node state which helps to decide whether to start a sub-protocol
    int MAX_PARTNERS;                                         // max number of partners
    int num_partners;                                         // current number of accepted partners
    int LEAST_NUMBER_PARTNERS;                                // the least required number of partners
    bool needMoreNeighbours;
    bool nodeFailure;
    int numberOfAlive;

    std::map<int , neighbour_info*> neighbours_map;           // node id -> node information (node=neighbour)
    std::queue<partner_request_item*> partner_request_queue;  // queue with pending partner requests (required if connections must be closed first)
    partner_request_item *current_partner_request;            // when requesting partners, this is used to remember the current and previous potential partners

    std::map<int,node_info*> network_nodes;

    int MESSAGE_TIMEOUT;
    int HEARTBEAT_NORMAL_TIME;
    int ALIVE_HEARTBEAT_TIMER;
    int PARTNER_ALIVE_TIMEOUT;
    cMessage *awakeMsgTimer;
    cMessage *heartbeatTimer;
    cMessage *startPartnerProbingTimer;

    void broadcastProbePingMsg();
    void aliveHeartbeat();
    void broadcastAliveMsg();
    void startPartnerProbing();
//    void sendProbePingMsg(int gateId);                        // TODO needs serious re-implementation (not in use for now)
    void handleProbePingMsg(PingPayload *pp_packet);
    void handleProbePongMsg(PingPayload *pp_packet);
    void handleProbeTimeoutMsg(TimeoutMsg *to_msg);

    void handlePartnerAliveTimeoutMsg(TimeoutMsg *to_msg);
    void rescheduleIsAliveTimeout(IPv4Address partner);
    void handleAliveMsg(PingPayload *pp_packet);

    void sendPartnerHelloMsg(IPv4Address src);
    void handlePartnerHelloMsg(PingPayload *pp_packet);
    void handlePartnerAgreeMsg(PingPayload *pp_packet);
    void handlePartnerConfirmMsg(PingPayload *pp_packet);
    void handlePartnerDeclineMsg(PingPayload *pp_packet);
    void handlePartnerAgreeTimeoutMsg(TimeoutMsg *to_msg);
    void handlePartnerConfirmTimeoutMsg(TimeoutMsg *to_msg);

    void sendCloseNotificationMsg(IPv4Address src);
    void handleCloseNotificationMsg(PingPayload *pp_packet);
    void handleCloseAcceptMsg(PingPayload *pp_packet);
    void handleCloseDenialMsg(PingPayload *pp_packet);
    void handleCloseAcceptTimeoutMsg(TimeoutMsg *to_msg);
    int nextPotentialPartners();

  // helper functions
    IPv4Address* findNextPotentialPartner();
    IPv4Address* findNextPotentialConnectionCloseModule();
    void incrementPartners();
    void decrementPartners();
    void meterHandlingLogic(cMessage* msg);

    //MCU Functions TODO the MCU should just have its own class def
    void handleNodeUpdate(PingPayload* msg);
    void handlePartnerReport(PingPayload* pp_packet);
    void sendNewPartnerUpdate(unsigned int partnerId);
};

}

#endif /* SMARTPROTOCOL_H_ */
