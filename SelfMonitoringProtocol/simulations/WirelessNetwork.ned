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

package selfmonitoringprotocol.simulations;

import inet.networklayer.autorouting.ipv4.IPv4NetworkConfigurator;
import inet.nodes.inet.AdhocHost;
import inet.world.radio.IdealChannelModel;
import selfmonitoringprotocol.Meter;


network WirelessNet
{
    parameters:
        //int numHosts;
        @display("bgb=850,800");
    submodules:
        channelControl: IdealChannelModel {
            parameters:
                @display("p=43,19");
        }
        configurator: IPv4NetworkConfigurator {
            config = xml("<config><interface hosts='*' address='192.168.x.x' netmask='255.255.0.0'/></config>");
            @display("p=38,74");
        }
        mcu: Meter {
            @display("p=427,65;i=device/antennatower;is=l");
        }
//        meter1: Meter {
//            @display("p=261,315;i=misc/house");
//        }
//        meter2: Meter {
//            @display("p=261,143;i=misc/house");
//        }
//        meter3: Meter {
//            @display("p=153,143;i=misc/house");
//        }
//        meter4: Meter {
//            @display("p=153,230;i=misc/house");
//        }
//        meter5: Meter {
//            @display("p=261,230;i=misc/house");
//        }
//        meter6: Meter {
//            @display("p=261,415;i=misc/house");
//        }
//        meter7: Meter {
//            @display("p=153,415;i=misc/house");
//        }
//        meter8: Meter {
//            @display("p=267,499;i=misc/house");
//        }
//        meter9: Meter {
//            @display("p=153,499;i=misc/house");
//        }
//        meter10: Meter {
//            @display("p=153,315;i=misc/house");
//        }
        meter11: Meter {
            @display("p=483,315;i=misc/house");
        }
        meter12: Meter {
            @display("p=483,143;i=misc/house");
        }
        meter13: Meter {
            @display("p=375,143;i=misc/house");
        }
        meter14: Meter {
            @display("p=375,230;i=misc/house");
        }
        meter15: Meter {
            @display("p=483,230;i=misc/house");
        }
        meter16: Meter {
            @display("p=483,415;i=misc/house");
        }
        meter17: Meter {
            @display("p=375,415;i=misc/house");
        }
        meter18: Meter {
            @display("p=489,499;i=misc/house");
        }
        meter19: Meter {
            @display("p=375,499;i=misc/house");
        }
        meter20: Meter {
            @display("p=375,315;i=misc/house");
        }
//        meter21: Meter {
//            @display("p=695,309;i=misc/house");
//        }
//        meter22: Meter {
//            @display("p=695,137;i=misc/house");
//        }
//        meter23: Meter {
//            @display("p=587,143;i=misc/house");
//        }
//        meter24: Meter {
//            @display("p=587,224;i=misc/house");
//        }
//        meter25: Meter {
//            @display("p=695,224;i=misc/house");
//        }
//        meter26: Meter {
//            @display("p=695,409;i=misc/house");
//        }
//        meter27: Meter {
//            @display("p=587,409;i=misc/house");
//        }
//        meter28: Meter {
//            @display("p=701,493;i=misc/house");
//        }
//        meter29: Meter {
//            @display("p=587,493;i=misc/house");
//        }
//        meter30: Meter {
//            @display("p=587,309;i=misc/house");
//        }
}
