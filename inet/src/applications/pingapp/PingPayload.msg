//
// Copyright (C) 2005 Andras Varga
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//


cplusplus {{
#include "INETDefs.h"
}}



//
// Represents payload in an ICMP/ICMPv6 Echo Request/Reply.
//
// TODO: move originator id and sequence number to ICMPMessage and use an ICMPControlInfo
packet PingPayload
{
    long originatorId; // sender module id
    long seqNo; // sequence number
    
    //Brian Mwambazi Hack: We put our fields here
    unsigned short pktType;//This is needed by the under laying protocols, do not remove
    unsigned short currPartners;//the current number of partners
    int partners[]; 
    int partnerId; 
    string senderName;
    // Daniel Hack:
    int num_neighbours;          // current number of partners of sending node
    int node_status;             // e.g. Fully_engaged when declining partnership
    //End of Hack
    
    unsigned char data[];
}
