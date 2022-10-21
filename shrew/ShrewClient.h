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

#ifndef SHREWCLIENT_H_
#define SHREWCLIENT_H_

#include "inet/applications/tcpapp/TcpBasicClientApp.h"
#include "inet/common/lifecycle/ILifecycle.h"
#include "inet/common/lifecycle/NodeStatus.h"

using namespace inet;

class ShrewClient: public TcpBasicClientApp {
protected:
    virtual void socketDataArrived(TcpSocket *socket, Packet *msg, bool urgent) override;
    virtual void handleStartOperation(LifecycleOperation *operation) override;
    virtual void sendRequest() override;
public:
    ShrewClient() {};
    virtual ~ShrewClient() {};
};

#endif /* SHREWCLIENT_H_ */
