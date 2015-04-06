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

#include "SmartProtocol.h"
#include "PingPayload_m.h"
#include "IPvXAddressResolver.h"
#include "IPv4ControlInfo.h"
#include "IPv6ControlInfo.h"
#include "ModuleAccess.h"
#include "NodeOperations.h"

using std::cout;


namespace selfmonitoringprotocol {
Define_Module(SmartProtocol);
SmartProtocol::SmartProtocol() {
    num_partners=0;

}

SmartProtocol::~SmartProtocol() {
    cancelAndDelete(heartbeatTimer);
    cancelAndDelete(awakeMsgTimer);
    cancelAndDelete(startPartnerProbingTimer);

}

/*
 * Initialization happens here, assign all fields needs assigning here under stage 0.
 */
void SmartProtocol::initialize(int stage)
{
    cSimpleModule::initialize(stage);

    if (stage == 0)
    {
        sendToMCU = (bool)par("sendToMCU");
        isMCU = (bool)par("isMCU");
        nodeFailure=(bool)par("nodeFailure");
        MESSAGE_TIMEOUT=(int)par("messageTimeout");
        MAX_PARTNERS=(int)par("maxPartners");
        LEAST_NUMBER_PARTNERS=(int)par("leastPartners");
        HEARTBEAT_NORMAL_TIME = MESSAGE_TIMEOUT +2;//TODO not a good idea to use timeout time,maybe we should have a time unit
        ALIVE_HEARTBEAT_TIMER=5;
        PARTNER_ALIVE_TIMEOUT= ALIVE_HEARTBEAT_TIMER * 3;
        pid=-1;
        needMoreNeighbours=true;
        heartbeatTimer = new cMessage("heartbeat");
        startPartnerProbingTimer=new cMessage("startPartnerProbingTimer");
        awakeMsgTimer=new cMessage("awakeMsgTimer");
        this->node_com_state=Wait_state;
        numberOfAlive=0;

    }
    else if (stage == 3)
    {
        startRunning();
    }
}

bool SmartProtocol::handleOperationStage(LifecycleOperation *operation, int stage, IDoneCallback *doneCallback)
{
    Enter_Method_Silent();
    if (dynamic_cast<NodeStartOperation *>(operation)) {
        if (stage == NodeStartOperation::STAGE_APPLICATION_LAYER )
            startRunning();
    }
    else if (dynamic_cast<NodeShutdownOperation *>(operation)) {
        if (stage == NodeShutdownOperation::STAGE_APPLICATION_LAYER)
            stopRunning();
    }
    else if (dynamic_cast<NodeCrashOperation *>(operation)) {
        if (stage == NodeCrashOperation::STAGE_CRASH)
            stopRunning();
    }
    else throw cRuntimeError("Unsupported lifecycle operation '%s'", operation->getClassName());
    return true;
}



void SmartProtocol::handleMessage(cMessage *msg)
{
    if(isMCU)
    {
        PingPayload *pp_packet = NULL;
        switch (msg->getKind()) {
            case Report_partner_status_msg:
                pp_packet = check_and_cast<PingPayload*>(msg);
                handlePartnerReport(pp_packet);
                break;
            case Node_update_msg:
                pp_packet = check_and_cast<PingPayload*>(msg);
                handleNodeUpdate(pp_packet);
                break;
            default:
                delete msg;
                break;
        }
    }else
    {
        meterHandlingLogic(msg);
    }

}

void SmartProtocol::handleNodeUpdate(PingPayload* msg){
    IPv4ControlInfo *ctrl=check_and_cast<IPv4ControlInfo *>(msg->getControlInfo());
    IPv4Address src = ctrl->getSrcAddr();

    if(network_nodes.find(src.getInt())==network_nodes.end()){
        network_nodes[src.getInt()]=new node_info();
        network_nodes[src.getInt()]->ipAddress=src;
        network_nodes[src.getInt()]->nodeId=src.getInt();
        network_nodes[src.getInt()]->nodeName=msg->getSenderName();
    }
    network_nodes[src.getInt()]->status=Running;

    partner_item *item=new partner_item();
    item->partnerId=msg->getPartnerId();
    item->reportsAsDead=false;
    network_nodes[src.getInt()]->partners.push_back(item);

    delete msg;
}

void SmartProtocol::handlePartnerReport(PingPayload* msg){
    IPv4ControlInfo *ctrl=check_and_cast<IPv4ControlInfo *>(msg->getControlInfo());
    IPv4Address src = ctrl->getSrcAddr();

    int nodeReported=msg->getPartnerId();
    bool allReportsDead=true;
    if(network_nodes.find(nodeReported)!=network_nodes.end()){
        network_nodes[nodeReported]->status=Suspect;

        for(unsigned int i=0;i<network_nodes[nodeReported]->partners.size();i++){

            if(network_nodes[nodeReported]->partners[i]->partnerId == src.getInt()){
                network_nodes[nodeReported]->partners[i]->reportsAsDead=true;
            }

            if(!network_nodes[nodeReported]->partners[i]->reportsAsDead)allReportsDead=false;
        }

        if(allReportsDead){//node is dead
            network_nodes[nodeReported]->status=Dead;
        }
    }

    delete msg;
}




void SmartProtocol::meterHandlingLogic(cMessage* msg) {
    if (msg == heartbeatTimer)
      {
          heartbeat();
          return;
      }
      else if(msg==startPartnerProbingTimer)
      {
          startPartnerProbing();
          return;
      }
      else if(msg==awakeMsgTimer)
      {
          aliveHeartbeat();
          return;
      }

    PingPayload *pp_packet = NULL;
    TimeoutMsg *to_msg = NULL;
    switch (msg->getKind()) {
    // Probe messages
    case Probe_ping_msg:
        pp_packet = check_and_cast<PingPayload*>(msg);
        handleProbePingMsg(pp_packet);
        break;
    case Probe_pong_msg:
        pp_packet = check_and_cast<PingPayload*>(msg);
        handleProbePongMsg(pp_packet);
        break;
        // Partner handshake messages
    case Partner_hello_msg:
        pp_packet = check_and_cast<PingPayload*>(msg);
        handlePartnerHelloMsg(pp_packet);
        break;
    case Partner_agree_msg:
        pp_packet = check_and_cast<PingPayload*>(msg);
        handlePartnerAgreeMsg(pp_packet);
        break;
    case Partner_confirm_msg:
        pp_packet = check_and_cast<PingPayload*>(msg);
        handlePartnerConfirmMsg(pp_packet);
        break;
    case Partner_decline_msg:
        pp_packet = check_and_cast<PingPayload*>(msg);
        handlePartnerDeclineMsg(pp_packet);
        break;
    case Partner_agree_timeout_msg:
        to_msg = dynamic_cast<TimeoutMsg*>(msg);
        handlePartnerAgreeTimeoutMsg(to_msg);
        break;
    case Partner_confirm_timeout_msg:
        to_msg = dynamic_cast<TimeoutMsg*>(msg);
        handlePartnerConfirmTimeoutMsg(to_msg);
        break;
    case Alive_msg:
        pp_packet = check_and_cast<PingPayload*>(msg);
        handleAliveMsg(pp_packet);
        break;
    case Partner_alive_timeout_msg:
        to_msg = dynamic_cast<TimeoutMsg*>(msg);
        handlePartnerAliveTimeoutMsg(to_msg);
        break;
        // Closing connection messages
    case Close_notification_msg:
        pp_packet = check_and_cast<PingPayload*>(msg);
        handleCloseNotificationMsg(pp_packet);
        break;
    case Close_accept_msg:
        pp_packet = check_and_cast<PingPayload*>(msg);
        handleCloseAcceptMsg(pp_packet);
        break;
    case Close_denial_msg:
        pp_packet = check_and_cast<PingPayload*>(msg);
        handleCloseDenialMsg(pp_packet);
        break;
    case Close_accept_timeout_msg:
        to_msg = dynamic_cast<TimeoutMsg*>(msg);
        handleCloseAcceptTimeoutMsg(to_msg);
        break;
    default:
        delete msg;
        break;
    }
}

//This should always be upto date with the node_status enum
static inline std::string getNodeStatus(node_status s){
    std::string values[]={"Running","Suspect","Dead"};
    return values[s];
}

static inline std::string getReportedStateAsString(bool state){
    return state? "down": "Up";
}

void SmartProtocol::finish()
{
    int count=1;
    if(isMCU){
        cout << "\n";
        cout << "--------------------------------------------------------" << endl;
        cout << "\t" <<getParentModule()->getName() <<" : Network State"<< endl;
        cout << "--------------------------------------------------------" << endl;

        cout<< "Node Name \t Nodes State \t Partners Reported States " <<endl;
        for(std::map<int,node_info*>::iterator it=network_nodes.begin();it!=network_nodes.end();it++ ){

            cout<< count <<"."<< it->second->nodeName <<"\t   " << getNodeStatus(it->second->status)  << "\t ";
            for(unsigned int i=0;i< it->second->partners.size();i++){
                cout<<network_nodes[it->second->partners[i]->partnerId]->nodeName <<":" <<getReportedStateAsString(it->second->partners[i]->reportsAsDead) <<" , ";
            }
            cout<<endl;
            count++;

        }


    }else{
        cout << "\n";
        cout << "--------------------------------------------------------" << endl;
        cout << "\t" <<getParentModule()->getName() <<" : Current Partners"<< endl;
        cout << "--------------------------------------------------------" << endl;

        cout <<"  Partner ID \t Partner Name \t Partner IP "<<endl;
        for(std::map<int , neighbour_info*>::iterator it= neighbours_map.begin(); it != neighbours_map.end(); it++) {
            if(it->second->con_status==Partners){
                cout << count <<"."<<it->second->ipAddress.getInt() << "\t " <<it->second->nodeName << "\t " <<it->second->ipAddress <<endl;
                count++;
            }

        }
    }
}



void SmartProtocol::processReceivedMessage(PingPayload* msg)
{
    IPv4ControlInfo *ctrl=check_and_cast<IPv4ControlInfo *>(msg->getControlInfo());
    IPv4Address src = ctrl->getSrcAddr();//retrieve the sender
    if(strcmp(msg->getName(),"Hello")==0)
    {//sure we all them a reply :)
        PingPayload *reply = new PingPayload("Hi there welcome");
        sendMessage(reply,src);
    }else
        EV << "YESS WE GOT A REPLY from " << src;
    delete msg;//clean up
}

/*
 * This  will run this to start the simulation.Put code that kick starts the protocol here
 */
void SmartProtocol::startRunning()
{
    pid = simulation.getUniqueNumber();
    if(sendToMCU)
    {
        scheduleAt(simTime() + 1.0, heartbeatTimer);
    }
}

void SmartProtocol::stopRunning()
{
    cancelEvent(heartbeatTimer);
    cancelEvent(awakeMsgTimer);
}


/*
 * Send message by specifying IPv4Address object of the destination
 */
void SmartProtocol::sendMessage(PingPayload* msg,IPv4Address destAddr)
{
    if (srcAddr.isUnspecified())
          srcAddr = IPvXAddressResolver().resolve(par("srcAddr"));

    EV << "Sending: destination = " << destAddr << "  source = " << srcAddr << "\n";
    msg->setByteLength(56);
    msg->setPktType(1);
    msg->setSenderName(getParentModule()->getName());
    // send to IPv4
    IPv4ControlInfo *ctrl = new IPv4ControlInfo();
    ctrl->setSrcAddr(srcAddr.get4());
    ctrl->setDestAddr(destAddr);
    ctrl->setTimeToLive(32);
    msg->setControlInfo(ctrl);
    send(msg, "pingOut");
    sendSeqNo++;
}

/*
 * Send message by specifying the address as a string.Accepts dotted decimal notation ("127.0.0.1"),
 * module name of the host
 */
void SmartProtocol::sendMessage(PingPayload* msg, const char* destAddrString)
{
    if (srcAddr.isUnspecified())
          srcAddr = IPvXAddressResolver().resolve(par("srcAddr"));

    IPvXAddress destAddr = IPvXAddressResolver().resolve(destAddrString);

    EV << "Starting up: destination = " << destAddr << "  source = " << srcAddr << "\n";

    msg->setOriginatorId(pid);
    msg->setSeqNo(sendSeqNo);
    msg->setByteLength(56);
    msg->setPktType(1);
    msg->setSenderName(getParentModule()->getName());

    if (!destAddr.isIPv6())
    {
        // send to IPv4
        IPv4ControlInfo *ctrl = new IPv4ControlInfo();
        ctrl->setSrcAddr(srcAddr.get4());
        ctrl->setDestAddr(destAddr.get4());
        ctrl->setTimeToLive(32);
        if(strcmp(destAddrString,"255.255.255.255")==0)//broadcasts need the interface id
            ctrl->setInterfaceId(101);//101 for wireless

        msg->setControlInfo(ctrl);
        send(msg, "pingOut");
    }
    else
    {
        // send to IPv6
        IPv6ControlInfo *ctrl = new IPv6ControlInfo();
        ctrl->setSrcAddr(srcAddr.get6());
        ctrl->setDestAddr(destAddr.get6());
        ctrl->setHopLimit(32);
        msg->setControlInfo(ctrl);
        send(msg, "pingv6Out");
    }
    sendSeqNo++;
}


/*************************************************************************
 * Protocol function                                                     *
 *************************************************************************/
void SmartProtocol::heartbeat()
{
    //1.Check if you need to discover more neighbours,if so initiate probing
    if(needMoreNeighbours){
        EV << "PROBING.........";
        broadcastProbePingMsg();
        scheduleAt(simTime() + 6.0, heartbeatTimer);
        return;
    }
    //2.if 1 passed check if you need to form partnerships,if so initiate partner probing
   if(num_partners < LEAST_NUMBER_PARTNERS){

        IPv4Address *partner= findNextPotentialPartner();

        if(partner == NULL){
            needMoreNeighbours=true;
        }
        else{
            sendPartnerHelloMsg(*partner);
        }
    }

    scheduleAt(simTime() + HEARTBEAT_NORMAL_TIME, heartbeatTimer);
}

void SmartProtocol::aliveHeartbeat(){
        if(this->num_partners>0){
            broadcastAliveMsg();
            numberOfAlive++;
            scheduleAt(simTime() + ALIVE_HEARTBEAT_TIMER, awakeMsgTimer);
            if(nodeFailure && numberOfAlive > 5){
                this->getParentModule()->bubble("Node Crushed!");
                this->stopRunning();
            }
        }
}

void SmartProtocol::broadcastAliveMsg(){
    PingPayload *msg = new PingPayload("Alive_msg", Alive_msg);
    sendMessage(msg, "255.255.255.255");//We broadcast the message not knowing who is out there
}

void SmartProtocol::broadcastProbePingMsg() {
    PingPayload *msg = new PingPayload("Probe_msg", Probe_ping_msg);
    sendMessage(msg, "255.255.255.255");//We broadcast the message not knowing who is out there

}



void SmartProtocol::startPartnerProbing()
{
    IPv4Address *partner=findNextPotentialPartner();
    //TODO
    //1.Check to see it we know at least one neighbour if no initiate neighbour discovery and schedule for another time
    if(partner == NULL)
    {
        broadcastProbePingMsg();
        scheduleAt(simTime()+ 6.0,startPartnerProbingTimer);
        return;
    }

    //2.solicit for partnerships,here since we cannot block we need to find a way of doing this using events
    sendPartnerHelloMsg(*partner);

}

void SmartProtocol::sendNewPartnerUpdate(unsigned int partnerId){
    PingPayload *packet=new PingPayload("Update_Partner_List",Node_update_msg);
    packet->setPartnerId(partnerId);
    sendMessage(packet,par("mcu"));
}

void SmartProtocol::handleProbePingMsg(PingPayload *pp_packet) {
    IPv4ControlInfo *ctrl = check_and_cast<IPv4ControlInfo *>(pp_packet->getControlInfo());
    IPv4Address src = ctrl->getSrcAddr();//retrieve the sender

    // if receiver doesn't know sender yet
    if (neighbours_map.find(src.getInt()) == neighbours_map.end()) {
        neighbours_map[src.getInt()] =  new neighbour_info();
        neighbours_map[src.getInt()]->com_state = Wait_state;
        neighbours_map[src.getInt()]->con_status = Discovered;
        neighbours_map[src.getInt()]->ipAddress = src;
        neighbours_map[src.getInt()]->nodeName=pp_packet->getSenderName();
        needMoreNeighbours=false;
    }
    PingPayload *reply = new PingPayload("Pong_msg", Probe_pong_msg);
    sendMessage(reply, src);
    delete pp_packet;

}

void SmartProtocol::handleProbePongMsg(PingPayload *pp_packet) {
    IPv4ControlInfo *ctrl=check_and_cast<IPv4ControlInfo *>(pp_packet->getControlInfo());
    IPv4Address src = ctrl->getSrcAddr();//retrieve the sender

    if (neighbours_map.find(src.getInt()) == neighbours_map.end()) {
        neighbours_map[src.getInt()] =  new neighbour_info();
        neighbours_map[src.getInt()]->com_state = Wait_state;
        neighbours_map[src.getInt()]->con_status = Discovered;
        neighbours_map[src.getInt()]->ipAddress = src;
        neighbours_map[src.getInt()]->nodeName=pp_packet->getSenderName();
        needMoreNeighbours=false;
    }

    delete pp_packet;
}

void SmartProtocol::handleAliveMsg(PingPayload *pp_packet){
    IPv4ControlInfo *ctrl=check_and_cast<IPv4ControlInfo *>(pp_packet->getControlInfo());
    IPv4Address src = ctrl->getSrcAddr();

    if(neighbours_map.find(src.getInt())!= neighbours_map.end() && neighbours_map[src.getInt()]->con_status==Partners ){
        EV << "Received Awake msg from : " << src;
        rescheduleIsAliveTimeout(src);
    }
    delete pp_packet;
}

void SmartProtocol::rescheduleIsAliveTimeout(IPv4Address partner) {
    TimeoutMsg *to_msg = neighbours_map[partner.getInt()]->is_alive_timeout;
    if (to_msg == NULL) {
        to_msg = new TimeoutMsg("Is Alive Timeout", Partner_alive_timeout_msg);
        to_msg->setModuleId(partner.getInt());
        neighbours_map[partner.getInt()]->is_alive_timeout=to_msg;
    } else {
        cancelEvent(to_msg);
    }
    scheduleAt(simTime()+PARTNER_ALIVE_TIMEOUT, to_msg);
}

void SmartProtocol::handlePartnerAliveTimeoutMsg(TimeoutMsg *msg){
    int partner=msg->getModuleId();
    EV << "Partner defaulted : " << neighbours_map[partner]->ipAddress;
    PingPayload *packet=new PingPayload("Report Partner",Report_partner_status_msg);
    packet->setPartnerId(partner);
    sendMessage(packet,par("mcu"));

    //neighbours_map[partner]->com_state = Wait_state;
    neighbours_map[partner]->con_status = Unknown;
    neighbours_map[partner]->is_alive_timeout=NULL;
    cancelAndDelete(msg);
}

void SmartProtocol::sendPartnerHelloMsg(IPv4Address src) {
    // don't start handshake when doing something else already
    if (this->node_com_state != Wait_state) { return; }
    this->node_com_state = Request_partner_state;

    PingPayload *p_msg = new PingPayload("Partner_hello_msg", Partner_hello_msg);
    p_msg-> setCurrPartners(this->num_partners);
    sendMessage(p_msg, src);

    TimeoutMsg *timeout_msg = new TimeoutMsg("Partner agree timeout", Partner_agree_timeout_msg);
    timeout_msg->setModuleId(src.getInt());
    if (neighbours_map.find(src.getInt()) == neighbours_map.end()) {
        neighbours_map[src.getInt()] = new neighbour_info();
        neighbours_map[src.getInt()]->con_status = Discovered;
    }
    neighbours_map[src.getInt()]->com_state = Request_partner_state;
    neighbours_map[src.getInt()]->timeout_event = timeout_msg;

    if(current_partner_request == NULL)
    {current_partner_request=new partner_request_item();}

    //current_partner_request->requested_set.insert(src.getInt());
    //current_partner_request->ipAddress = src;

    scheduleAt(simTime()+MESSAGE_TIMEOUT, timeout_msg);
}

void SmartProtocol::handlePartnerHelloMsg(PingPayload *pp_packet) {
    IPv4ControlInfo *ctrl=check_and_cast<IPv4ControlInfo *>(pp_packet->getControlInfo());
    IPv4Address src = ctrl->getSrcAddr();//retrieve the sender

    // both nodes are requesting partnership and thus both agree on it
    if ((neighbours_map.find(src.getInt()) != neighbours_map.end())
            && (neighbours_map[src.getInt()]->com_state == Request_partner_state)) {
        handlePartnerAgreeMsg(pp_packet);
        return;
    }


    if ((neighbours_map.find(src.getInt()) == neighbours_map.end())
            || (neighbours_map[src.getInt()]->com_state != Wait_state)) {
        delete pp_packet; return;
    }

    neighbours_map[src.getInt()]->com_state = Handle_partner_request_state;

    // decide whether to accept or decline partnership
    // case 1: node has capabilities to accept new partners
    if (num_partners < MAX_PARTNERS) {
        // agree on partnership
        PingPayload *reply = new PingPayload("Partner_agree_msg", Partner_agree_msg);
        sendMessage(reply, src);

        // set timeout for waiting for confirmation
        TimeoutMsg *timeout_msg = new TimeoutMsg("partner confirmation timeout", Partner_confirm_timeout_msg);
        neighbours_map[src.getInt()]->timeout_event = timeout_msg;
        scheduleAt(simTime()+MESSAGE_TIMEOUT, timeout_msg);

    } else {
    // case 2a) requester already has LEAST_NUMBER_NEIGHBOURS
        if (LEAST_NUMBER_PARTNERS <= pp_packet->getNum_neighbours()) {
            // decline partnership
            PingPayload *reply = new PingPayload("Partner_decline_msg", Partner_decline_msg);
            reply->setNode_status(Fully_engaged);
            sendMessage(reply, src);

            neighbours_map[src.getInt()]->com_state = Wait_state;

        } else {
    // case 2b) requester has less than  (need to accept!)
            // 1) check if "num_partners > LEAST_NUMBER_NEIGHBOURS"
            if (num_partners > LEAST_NUMBER_PARTNERS) {
                partner_request_item *item = new partner_request_item();
                item->ipAddress = src;
                partner_request_queue.push(item);

                if (partner_request_queue.size() == 1) {  // no other module is waiting for partnership
                // select partner with "num_partners > LEAST_NUMBER_NEIGHBOURS"
                    IPv4Address *potentialClose = findNextPotentialConnectionCloseModule();
                    if (potentialClose != NULL) {
                        sendCloseNotificationMsg(*potentialClose);
                        // agree on partnership
                        IPv4Address req_ipAddr = partner_request_queue.front()->ipAddress;
                        PingPayload *reply = new PingPayload("Partner_agree_msg", Partner_agree_msg);
                        sendMessage(reply, req_ipAddr);

                        // set timeout for waiting for confirmation
                        TimeoutMsg *timeout_msg = new TimeoutMsg("partner confirmation timeout", Partner_confirm_timeout_msg);
                        neighbours_map[src.getInt()]->timeout_event = timeout_msg;
                        scheduleAt(simTime()+MESSAGE_TIMEOUT, timeout_msg);
                    } else {
                        // no connection can be closed and node must decline partnership
                        PingPayload *decline = new PingPayload("Partner_decline_msg", Partner_decline_msg);
                        IPv4Address req_ipAddr = partner_request_queue.front()->ipAddress;
                        sendMessage(decline, req_ipAddr);
                        partner_request_queue.pop();
                    }


                }

            /*
             * Problems to consider here:
             * - timeout with partner request due to wait for close messages
             * - need to remember request while waiting for close message replies (steps 2)+3))
             * - what if partner already got other partner in the mean time?
             * - race conditions with num_partners of other partners
             */

            } else {
            // not enough partners to risk losing one
                PingPayload *reply = new PingPayload("Partner_decline_msg", Partner_decline_msg);
                reply->setNode_status(Fully_engaged);
                sendMessage(reply, src);

                neighbours_map[src.getInt()]->com_state = Wait_state;
            }
        }
    }
    delete pp_packet;
}

void SmartProtocol::incrementPartners() {
    num_partners++;
    char num[64];
    sprintf(num, "Partners %d", num_partners);
    this->getParentModule()->bubble(num);
}

void SmartProtocol::decrementPartners() {
    num_partners--;
    char num[64];
    sprintf(num, "Partners %d", num_partners);
    this->getParentModule()->bubble(num);
}

void SmartProtocol::handlePartnerAgreeMsg(PingPayload *pp_packet) {
    IPv4ControlInfo *ctrl=check_and_cast<IPv4ControlInfo *>(pp_packet->getControlInfo());
    IPv4Address src = ctrl->getSrcAddr();//retrieve the sender

    // protect from randomly sent message
    if ((neighbours_map.find(src.getInt()) == neighbours_map.end())
            || (neighbours_map[src.getInt()]->com_state != Request_partner_state)) {
        delete pp_packet; return;
    }

    // change status
    neighbour_info *info = neighbours_map[src.getInt()];
    info->con_status = Partners;
    incrementPartners();
    sendNewPartnerUpdate(src.getInt());
    // send confirmation
    PingPayload *reply = new PingPayload("Partner_confirm_msg", Partner_confirm_msg);
    sendMessage(reply, src);

    this->node_com_state = Wait_state;
    // remove agree timeout message
    cancelAndDelete(info->timeout_event);
    neighbours_map[src.getInt()]->timeout_event = NULL;
    delete pp_packet;
    this->node_com_state = Wait_state;
    current_partner_request = NULL;

    rescheduleIsAliveTimeout(src);//start watching it
    if(num_partners==1)
        scheduleAt(simTime() + (MESSAGE_TIMEOUT*2), awakeMsgTimer);//allow time for confirmation to reach the other party
    /*if (num_partners < LEAST_NUMBER_PARTNERS) {
        startPartnerProbing();
    } else {
        // allow doing something else again
        this->node_com_state = Wait_state;
        current_partner_request = NULL;
    }*/
}

void SmartProtocol::handlePartnerConfirmMsg(PingPayload *pp_packet) {
    IPv4ControlInfo *ctrl=check_and_cast<IPv4ControlInfo *>(pp_packet->getControlInfo());
    IPv4Address src = ctrl->getSrcAddr();//retrieve the sender

    int ip_Addr = src.getInt();
    // protect from randomly sent message
    if ((neighbours_map.find(ip_Addr) != neighbours_map.end())
            && (neighbours_map[ip_Addr]->com_state == Handle_partner_request_state)) {
        neighbours_map[ip_Addr]->com_state = Wait_state;
        neighbours_map[ip_Addr]->con_status = Partners;

        incrementPartners();
        sendNewPartnerUpdate(src.getInt());
        // remove confirm timeout message
        TimeoutMsg *timeout = neighbours_map[ip_Addr]->timeout_event;
        cancelAndDelete(timeout);
        neighbours_map[ip_Addr]->timeout_event = NULL;

        rescheduleIsAliveTimeout(src);//start watching it
        if(num_partners==1)
                scheduleAt(simTime() + 2, awakeMsgTimer);//start right away
    }
    delete pp_packet;
}

void SmartProtocol::handlePartnerDeclineMsg(PingPayload *pp_packet) {
    IPv4ControlInfo *ctrl = check_and_cast<IPv4ControlInfo *>(pp_packet->getControlInfo());
    IPv4Address src = ctrl->getSrcAddr();//retrieve the sender

    int ip_Addr = src.getInt();
    // protect from randomly sent message
    if ((neighbours_map.find(ip_Addr) != neighbours_map.end())
            && (neighbours_map[ip_Addr]->com_state == Request_partner_state)) {
        neighbours_map[ip_Addr]->com_state = Wait_state;

        // remove agree timeout message
        TimeoutMsg *timeout = neighbours_map[ip_Addr]->timeout_event;
        cancelAndDelete(timeout);
/*
        // ask next potential partner if necessary
        if (num_partners < LEAST_NUMBER_PARTNERS) {
            startPartnerProbing();
        }*/
    }
    delete pp_packet;
}

void SmartProtocol::handlePartnerAgreeTimeoutMsg(TimeoutMsg *to_msg) {
    // TODO just drop message? or even remove other node from list?Or just increment the number of failed attempts
    if ((to_msg != NULL) && (to_msg->isSelfMessage())
            && (neighbours_map.find(to_msg->getModuleId()) != neighbours_map.end())) {
        neighbours_map[to_msg->getModuleId()]->com_state = Wait_state;
        neighbours_map[to_msg->getModuleId()]->timeout_event = NULL;
        this->node_com_state = Wait_state;

    }
    delete to_msg;
}

void SmartProtocol::handlePartnerConfirmTimeoutMsg(TimeoutMsg *to_msg) {
    // TODO just drop message? or even remove other node from list?
    if ((to_msg != NULL) && (to_msg->isSelfMessage())
            && (neighbours_map.find(to_msg->getModuleId()) != neighbours_map.end())) {
        neighbours_map[to_msg->getModuleId()]->com_state = Wait_state;
        neighbours_map[to_msg->getModuleId()]->timeout_event = NULL;
    }
    delete to_msg;
}

void SmartProtocol::sendCloseNotificationMsg(IPv4Address src) {
    PingPayload *msg = new PingPayload("Close_notification_msg", Close_notification_msg);
    sendMessage(msg, src);

    neighbours_map[src.getInt()]->com_state = Close_connection_state;

    // set timeout for Close timeout message
    TimeoutMsg *timeout_msg = new TimeoutMsg("Close_accept_timeout_msg", Close_accept_timeout_msg);
    neighbours_map[src.getInt()]->timeout_event = timeout_msg;
    scheduleAt(simTime()+MESSAGE_TIMEOUT, timeout_msg);
}

void SmartProtocol::handleCloseNotificationMsg(PingPayload *pp_packet) {
    IPv4ControlInfo *ctrl=check_and_cast<IPv4ControlInfo *>(pp_packet->getControlInfo());
    IPv4Address src = ctrl->getSrcAddr();//retrieve the sender

    int ipAddr = src.getInt();
    // protect from randomly sent message
    if ((neighbours_map.find(ipAddr) == neighbours_map.end())
            || (neighbours_map[ipAddr]->con_status != Partners)
            || (neighbours_map[ipAddr]->com_state != Wait_state)){
        delete pp_packet; return;
    }

    if (num_partners <= LEAST_NUMBER_PARTNERS) {
        // deny connection close
        PingPayload *deny_msg = new PingPayload("close denial", Close_denial_msg);
        // TODO add reason to message
        sendMessage(deny_msg, src);

    } else {
        // accept connection close
        neighbours_map[ipAddr]->con_status = Discovered;
        if (0 < num_partners) { decrementPartners(); }

        PingPayload *accept_msg = new PingPayload("close accept", Close_accept_msg);
        sendMessage(accept_msg, src);
    }
    delete pp_packet;
}

void SmartProtocol::handleCloseAcceptMsg(PingPayload *pp_packet) {
    IPv4ControlInfo *ctrl=check_and_cast<IPv4ControlInfo *>(pp_packet->getControlInfo());
    IPv4Address src = ctrl->getSrcAddr();//retrieve the sender

    // protect from randomly sent message
    if ((neighbours_map.find(src.getInt()) == neighbours_map.end())
            || (neighbours_map[src.getInt()]->com_state != Close_connection_state)){
        delete pp_packet; return;
    }
    neighbours_map[src.getInt()]->con_status = Discovered;
    if (0 < num_partners) { num_partners--; }
    neighbours_map[src.getInt()]->com_state = Wait_state;

    // go back to handling partner request
    // agree on partnership
    PingPayload *agree = new PingPayload("Partner_agree_msg", Partner_agree_msg);
    IPv4Address req_ipAddr = partner_request_queue.front()->ipAddress;
    sendMessage(agree, req_ipAddr);
    partner_request_queue.pop();

    // set timeout for waiting for confirmation
    TimeoutMsg *timeout_msg = new TimeoutMsg("partner confirmation timeout", Partner_agree_timeout_msg);
    neighbours_map[req_ipAddr.getInt()]->timeout_event = timeout_msg;
    scheduleAt(simTime()+MESSAGE_TIMEOUT, timeout_msg);

    IPv4Address *potentialClose = NULL;
    while ((partner_request_queue.size() >= 1) && (potentialClose == NULL)) {
        potentialClose = findNextPotentialConnectionCloseModule();
        if (potentialClose != NULL) {
            sendCloseNotificationMsg(*potentialClose);
        } else {
            // no connection can be closed and node must decline partnership
            PingPayload *decline = new PingPayload("Partner_decline_msg", Partner_decline_msg);
            req_ipAddr = partner_request_queue.front()->ipAddress;
            sendMessage(decline, req_ipAddr);
            partner_request_queue.pop();
        }
    }

    delete pp_packet;
}

void SmartProtocol::handleCloseDenialMsg(PingPayload *pp_packet) {
    IPv4ControlInfo *ctrl=check_and_cast<IPv4ControlInfo *>(pp_packet->getControlInfo());
    IPv4Address src = ctrl->getSrcAddr();//retrieve the sender

    // protect from randomly sent message
    if ((neighbours_map.find(src.getInt()) == neighbours_map.end())
            || (neighbours_map[src.getInt()]->com_state != Close_connection_state)){
        delete pp_packet; return;
    }
    neighbours_map[src.getInt()]->com_state = Wait_state;

    // select other partner for potential connection close
    if (partner_request_queue.size() >= 1) {
        partner_request_queue.front()->requested_set.insert(src.getInt());
        // select partner with "num_partners > LEAST_NUMBER_NEIGHBOURS"
        IPv4Address *potentialClose = findNextPotentialConnectionCloseModule();
        if (potentialClose != NULL) {
            sendCloseNotificationMsg(*potentialClose);
        } else {
            // decline partnership
            PingPayload *decline = new PingPayload("Partner_decline_msg", Partner_decline_msg);
            IPv4Address req_ipAddr = partner_request_queue.front()->ipAddress;
            sendMessage(decline, req_ipAddr);
            partner_request_queue.pop();

            IPv4Address *potentialClose = NULL;
            while ((partner_request_queue.size() >= 1) && (potentialClose == NULL)) {
                potentialClose = findNextPotentialConnectionCloseModule();
                if (potentialClose != NULL) {
                    sendCloseNotificationMsg(*potentialClose);
                } else {
                    // no connection can be closed and node must decline partnership
                    decline = new PingPayload("Partner_decline_msg", Partner_decline_msg);
                    req_ipAddr = partner_request_queue.front()->ipAddress;
                    sendMessage(decline, req_ipAddr);
                    partner_request_queue.pop();
                }
            }
        }
    }

    delete pp_packet;
}

void SmartProtocol::handleCloseAcceptTimeoutMsg(TimeoutMsg *to_msg) {
    // TODO just drop message? or even remove other node from list?
    if ((to_msg != NULL) && (to_msg->isSelfMessage())
            && (neighbours_map.find(to_msg->getModuleId()) != neighbours_map.end())) {
        neighbours_map[to_msg->getModuleId()]->com_state = Wait_state;
        neighbours_map[to_msg->getModuleId()]->timeout_event = NULL;

        IPv4Address* potentialClose = NULL;
        while ((partner_request_queue.size() >= 1) && (potentialClose == NULL)) {
            potentialClose = findNextPotentialConnectionCloseModule();
            if (potentialClose != NULL) {
                sendCloseNotificationMsg(*potentialClose);
            } else {
                // no connection can be closed and node must decline partnership
                PingPayload *decline = new PingPayload("Partner_decline_msg", Partner_decline_msg);
                IPv4Address req_moduleId = partner_request_queue.front()->ipAddress;
                sendMessage(decline, req_moduleId);
                partner_request_queue.pop();
            }
        }
    }
    delete to_msg;
}

IPv4Address* SmartProtocol::findNextPotentialPartner() {
    if (current_partner_request == NULL) {
        current_partner_request = new partner_request_item();
    }
    //std::set<int> req_set = current_partner_request->requested_set;
    for(std::map<int , neighbour_info*>::iterator it= neighbours_map.begin(); it != neighbours_map.end(); it++) {
        // of module is discovered, in wait-state and was not asked yet, return module id
        if ((it->second->con_status == Discovered) && (it->second->com_state == Wait_state)
                //&& (req_set.find(it->first) == req_set.end())
                ) {
            return &(it->second->ipAddress);
        }
    }
    return NULL;
}

IPv4Address* SmartProtocol::findNextPotentialConnectionCloseModule() {
    // iterate over neighbour map
    std::set<int> close_req_set = partner_request_queue.front()->requested_set;
    for(std::map<int , neighbour_info*>::iterator it= neighbours_map.begin(); it != neighbours_map.end(); it++) {
        // if module is partner, in wait-state and was not asked yet, return module id
        if ((it->second->con_status == Partners) && (it->second->com_state == Wait_state)
                && (close_req_set.find(it->first) == close_req_set.end())) {
            return &(it->second->ipAddress);
        }
    }
    return NULL;
}

} /* namespace testproject */

