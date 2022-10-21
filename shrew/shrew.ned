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

import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.inet.Router;
import inet.node.inet.StandardHost;
import ned.DatarateChannel;
import inet.applications.tcpapp.TcpBasicClientApp;

simple ShrewClient extends TcpBasicClientApp {
    parameters:
    	@class(ShrewClient);
    	double burstTime @unit(s) = default(1s);
}

network Shrew
{
    parameters:
        int n;
    types:
        channel Channel extends DatarateChannel
        {
            delay = 1us;
            datarate = 100Mbps;
        }
    submodules:
        configurator: Ipv4NetworkConfigurator {
            parameters:
                @display("p=100,100;is=s");
        }
        router: Router {
            @display("p=400,250");
        }
        client: StandardHost {
            parameters:
                @display("p=400,50");
        }
        bot[n]: StandardHost {
            parameters:
                @display("p=250,100,col,100;i=,#C01C28");
        }
        server: StandardHost {
            parameters:
                @display("i=device/server;p=650,250");
        }
    connections:
        for i=0..n-1 {
            bot[i].pppg++ <--> Channel <--> router.pppg++;
        }
        client.pppg++ <--> Channel <--> router.pppg++;
        router.pppg++ <--> Channel <--> server.pppg++;
}
