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

package selfmonitoringprotocol;

simple SmartProtocol like ISmartProtocol
{
    parameters:
        string mcu = default(""); // destination address
        string srcAddr = default(""); // source address (useful with multi-homing)
        double packetSize @unit("B") = default(56B); // of ping payload, in bytes
        double hopLimit = default(32); // TTL or hopLimit for IP packets
        @display("i=block/app");
        bool sendToMCU=default(false);
        bool isMCU=default(false);
        int messageTimeout=default(3);
        int maxPartners = default(5);
        int leastPartners = default(2);
        bool nodeFailure=default(false);
    gates:
        input pingIn @labels(PingPayload/up);
        output pingOut @labels(PingPayload/down);
        input pingv6In @labels(PingPayload/up);
        output pingv6Out @labels(PingPayload/down);
}
