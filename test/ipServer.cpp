#include "src/core_data.h"
#include "src/device.h"
#include "src/packetio.h"
#include "src/ip.h"
#include <iostream>
#include <thread>
#include <arpa/inet.h>
#include <cstring>


int main(int argc,char** argv){
    if (argc!=2){
        std::cerr <<"usage: "<<argv[0]<<" <client device name> "<<std::endl;
        return -1;
    }
    int client_id = pan_protocol_stack::device::addDevice(argv[1]);
    std::cout<<"Successfully Added!"<<std::endl;
    pan_protocol_stack::ethernet::setFrameReceiveCallback(pan_protocol_stack::ethernet::ether_broker_callback);
    pan_protocol_stack::ip::setIPPacketReceiveCallback(pan_protocol_stack::ip::defaultIPPacketHandler);
    std::cout<<"Successfully Bound!"<<std::endl;
    auto &d = pan_protocol_stack::device::get_device_handler(client_id);
    pan_protocol_stack::ethernet::start_capturing(client_id);
    return 0;
}