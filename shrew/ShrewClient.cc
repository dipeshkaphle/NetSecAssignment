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

#include "ShrewClient.h"

#include "inet/applications/tcpapp/GenericAppMsg_m.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/TimeTag_m.h"
#include "inet/common/lifecycle/ModuleOperations.h"
#include "inet/common/packet/Packet.h"

using namespace inet;

#define MSGKIND_SEND       1

void ShrewClient::socketDataArrived(TcpSocket *socket, Packet *msg, bool urgent)
{
    TcpAppBase::socketDataArrived(socket, msg, urgent);
}

void ShrewClient::handleStartOperation(LifecycleOperation *operation)
{
    TcpBasicClientApp::handleStartOperation(operation);
    simtime_t burstTime = par("burstTime");
    simtime_t sendSchedule = simTime() + burstTime;
    for (int i = 0; i < 10; i++) {
        cMessage* sendMessage = new cMessage("send");
        sendMessage->setKind(MSGKIND_SEND);
        scheduleAt(sendSchedule, sendMessage);
    }
}

void ShrewClient::sendRequest()
{
    TcpBasicClientApp::sendRequest();

    simtime_t burstTime = par("burstTime");
    simtime_t sendSchedule = simTime() + burstTime;
    cMessage* sendMessage = new cMessage("send");
    sendMessage->setKind(MSGKIND_SEND);
    scheduleAt(sendSchedule, sendMessage);
}

Define_Module(ShrewClient);
