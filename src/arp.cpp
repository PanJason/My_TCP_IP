#include "arp.h"
#include "device.h"
#include "packetio.h"
#include <arpa/inet.h>
#include <iostream>

namespace pan_protocol_stack{
namespace arp{
arp_table arp_neighbour;

bool defaultARPPacketHandler(uint16_t ethertype, const void * packetPtr, int packetLen, int dev_id){
    if(ethertype!=arp::ethertype) return 0;
    auto hdr = (arp_header*)packetPtr;
    auto hd_type = ntohs(hdr->hardware_type);
    auto proto_type = ntohs(hdr->protocol_type);
    auto opcode = ntohs(hdr->opcode);
    if(hd_type != 0x1 ||proto_type != 0x0800||hdr->hardware_len!=sizeof(ethernet::mac_addr)||hdr->protocol_len!=sizeof(ip::ip_addr)){
        std::cerr<<"Unsupported ARP Protocol"<<std::endl;
        return 0;
    }
    auto s_ip = ntohl(hdr->sender_ip);
    memcpy(arp_neighbour[s_ip].first.data, sender_mac, sizeof(ethernet::mac_addr));
    arp_neighbour[s_ip].second = TIMEOUT;
    auto device = device::get_device_handler(dev_id);
    if(opcode == 0x1){
        for (const auto &ip :device.ip_addrs){
            if (ip == ntohl(hdr->target_ip))
            {
                sendARPPacket(dev_id, 0x2, device.mac_address, ip, hdr->sender_mac, ntohl(hdr->sender_ip));

            }
        }
    }
    return 1;
}

int sendARPPacket(int dev_id, uint16_t opcode, const ethernet::mac_addr sender_mac, const ip::ip_addr sender_ip, const ethernet::mac_addr target_mac, const ip::ip_addr target_ip){
    auto packetLen = sizeof(arp_header);
    arp_header* hdr = (arp_header*)malloc(packetLen);
    hdr->hardware_type = htons((uint16_t)0x1);
    hdr->protocol_type = htons((uint16_t)0x0800);
    hdr->hardware_len = sizeof(ethernet::mac_addr);
    hdr->protocol_len = sizeof(ip::ip_addr);
    hdr->opcode = htons(opcode);
    memcpy(hdr->sender_mac, sender_mac, sizeof(ethernet::mac_addr));
    hdr->sender_ip = htonl(sender_ip);
    memcpy(hdr->target_mac, target_mac, sizeof(ethernet::mac_addr));
    hdr->target_ip = htonl(target_ip);
    bool res = ethernet::sendFrame(hdr, packetLen, arp::ethertype,target_mac, dev_id);
    return res;
}

bool search_arp(int dev_id, const ip::ip_addr dest, device::mac_wapper *result){
    device::device_t& d = device::get_device_handler(dev_id);
    for (const auto &ip : d.ip_addrs){
        if (ip == dest){
            memcpy(result->data, d.mac_address, sizeof(ethernet::mac_addr));
            return 1;
        }
    }
    if (arp_neighbour.find(dest) == arp_neighbour.end()){
        sendARPPacket(dev_id, 0x1, d.mac_address, d.ip_addrs, ethernet::ETHERNET_BROADCAST,dest);
        return 0;
    }
    else
    {
        //here may exist bugs in memcpy.
        memcpy(result->data, arp_neighbour[dest].first.data, sizeof(ethernet::mac_addr));
        return 1;                
    }
}

void decrease_time(){
  auto it = neighbor_map.begin();
  while (it != neighbor_map.end()) {
    if (it->second.second == 0) {
      neighbor_map.erase(it++);
      ++counter;
    } else {
      --(it++)->second.second;
    }
  }
}

}
}