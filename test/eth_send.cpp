#include "src/core_data.h"
#include "src/device.h"
#include "src/packetio.h"
#include <iostream>
#include <cstring>
#include <netinet/ether.h>

int main(int argc, char** argv){
    if (argc!=4){
        std::cerr <<"usage: "<<argv[0]<<" <client device name> <server MAC address> <Message> "<<std::endl;
        return -1;
    }
    int client_id = pan_protocol_stack::device::addDevice(argv[1]);
    pan_protocol_stack::ethernet::setFrameReceiveCallback(pan_protocol_stack::ethernet::print_callback);
    struct ether_addr *ea = ether_aton(argv[2]);
    int ret = pan_protocol_stack::ethernet::sendFrame(argv[3],strlen(argv[3]),0x0800,ea->ether_addr_octet, client_id);
    std::cout<<"Return value is "<<ret<<std::endl;
    return ret;
}