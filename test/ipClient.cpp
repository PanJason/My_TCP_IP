#include "src/core_data.h"
#include "src/device.h"
#include "src/packetio.h"
#include "src/ip.h"
#include <iostream>
#include <thread>
#include <arpa/inet.h>
#include <cstring>

int start_capturing(int dev_id,pan_protocol_stack::ip::ip_addr src, pan_protocol_stack::ip::ip_addr dst, const void *buf, int len){
    const u_char *packet;
    struct pcap_pkthdr *hdr;
    pan_protocol_stack::device::device_t d = pan_protocol_stack::device::get_device_handler(dev_id);
    int res;
    std::cout<<"Capturing at Mac Address "<<pan_protocol_stack::ethernet::mac2string(d.mac_address)<<std::endl;
    uint16_t count = 1;
    while((res = pcap_next_ex(d.pcap_handler, &hdr, &packet)) >=0 ){
        if(res == 0){
            std::cerr<<"Timeout!"<<std::endl;
        }
        int ret = pan_protocol_stack::core_data::get().ethernet_callback(packet, hdr->len,dev_id);
        if (ret<0) {
            std::cerr<<"Anomaly"<<std::endl;
        }
        pan_protocol_stack::ip::sendIPPacket(src,dst,17,0,count++,2,0,15,buf,len);		
    }
    if (res<0) return -1;
    return 0;
}

int main(int argc,char** argv){
    if (argc!=4){
        std::cerr <<"usage: "<<argv[0]<<" <client device name> <server IP address> <Message> "<<std::endl;
        return -1;
    }
    pan_protocol_stack::ethernet::setFrameReceiveCallback(pan_protocol_stack::ethernet::ether_broker_callback);
    pan_protocol_stack::ip::setIPPacketReceiveCallback(pan_protocol_stack::ip::defaultIPPacketHandler);
    int client_id = pan_protocol_stack::device::addDevice(argv[1]);
    auto &d = pan_protocol_stack::device::get_device_handler(client_id);
    //pan_protocol_stack::ip::setup(client_id);
    pan_protocol_stack::ip::ip_addr src = d.ip_addrs[0];
    pan_protocol_stack::ip::ip_addr dst = ntohl(inet_addr(argv[2]));
    std::cout<<"Trying to send my message!"<<std::endl;
    pan_protocol_stack::ip::sendIPPacket(d.ip_addrs[0],dst,17,0,0,2,0,15,argv[3],strlen(argv[3]));
    start_capturing(client_id,d.ip_addrs[0],dst, argv[3],strlen(argv[3]));
    return 0;
}