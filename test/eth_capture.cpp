#include "src/core_data.h"
#include "src/device.h"
#include "src/packetio.h"
#include <iostream>

int main(int argc, char** argv){
    if (argc!=2){
        std::cerr <<"usage: "<<argv[0]<<" <vnethX-X> "<<std::endl;
        return -1;
    }
    int server_id = pan_protocol_stack::device::addDevice(argv[1]);
    std::cout<<"Successfully Added!"<<std::endl;
    pan_protocol_stack::ethernet::setFrameReceiveCallback(pan_protocol_stack::ethernet::print_callback);
    std::cout<<"Successfully Binded!"<<std::endl;
    int ret =  pan_protocol_stack::ethernet::start_capturing(server_id);
    std::cout<<"Return value is "<<ret<<std::endl;
    return ret;
}