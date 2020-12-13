#define __IP_TEST_
#include "ip.h"
#include "core_data.h"
#include <iostream>
#include <arpa/inet.h>
#include <cstdlib>
#include <time.h>
#include <map>
#include <mutex>
#include <cstring>
#include <sstream>
#include <string>
#include <iostream>

namespace pan_protocol_stack{
namespace ip{
std::vector<struct route_item> routingTable;
std::map<struct flooding_record, int> record_map;
int setupClock = 0;
std::mutex mutexRoutingTable;
std::mutex mutexRecordMap;
std::mutex mutexSetupClock;

std::vector<struct route_item> &getRoutingTable() {return routingTable;}
std::string ip2string(const ip_addr &ip){
    std::ostringstream os;
    os<<((ip>>24)&(0xFF))<<"."<<((ip>>16)&(0xFF))<<"."<<((ip>>8)&(0xFF))<<"."<<(ip&(0xFF));
    return os.str();
}
int defaultIPPacketHandler(const void * packetPtr, int packetLen, int dev_id, int proto, const void *src_mac){
    auto hdr = (iphdr*)packetPtr;
    auto checksum = hdr->check;
    hdr->check = 0;
    hdr->check = ip_checksum(hdr,sizeof(iphdr));
    if(checksum!= hdr->check){
        std::cerr<<"Incorrect checksum"<<std::endl;
        #ifdef __IP_TEST_
        printIPHeader(hdr);
        #endif
        return -1;
    }
    bool target = 0;
    bool self_sent = 0;
    for (const auto &dev : core_data::get().devices){
        for (const auto &ip : dev->ip_addrs){
            target = (ip == ntohl(hdr->daddr)) | target;
            self_sent = (ip == ntohl(hdr->saddr)) | self_sent;
        }
    }
    //This part is used to deal with flooding routing requests
    if(hdr->protocol == ip::MY_ROUTING_PROTO){
        if(self_sent || hdr->ttl == 0){
            std::cerr<<"Self sent or dead packet!"<<std::endl;
            #ifdef __IP_TEST_
            printIPHeader(hdr);
            #endif
            return -1;
        }
        ip_addr src = ntohl(hdr->saddr);
        ip_addr dst = ntohl(hdr->daddr);
        uint16_t identification = ntohs(hdr->id);
        auto &d = device::get_device_handler(dev_id);

        //If first received save the record send the packet back and forward the packet.
        //forward routing packet.
        bool routingPacketSeen = checkAndSearchRecord(src,dst,ip::MY_ROUTING_PROTO,identification);
        if(!routingPacketSeen){
            addPacketRecord(src,dst,ip::MY_ROUTING_PROTO,identification);
            setRoutingTable(src, 0xFFFFFFFF, src_mac, d.device_name.c_str() );
            #ifdef __IP_TEST_
            std::cout<<"Received Routing IP packet from "<<ip2string(ntohl(hdr->saddr))<<" to "
            <<ip2string(ntohl(hdr->daddr))<<std::endl;
            printIPHeader(hdr);
            #endif
            if(!target&&!self_sent){
                sendIPPacket(src,dst,ip::MY_ROUTING_PROTO,0,identification, 0x2, 0, hdr->ttl - 1,0,0);
                srand((unsigned)time(NULL));
                sendIPPacket(d.ip_addrs[0],src,ip::MY_ROUTING_PROTO,0,rand()&(0xFFFFFFFF),0x2,0, 15,0,0);
            }
            return 0;
        }
        else
        {
            #ifdef __IP_TEST_
            std::cerr<<"Routing packet seen from "<<ip2string(ntohl(hdr->saddr))<<" to "
            <<ip2string(ntohl(hdr->daddr))<<std::endl;
            printIPHeader(hdr);
            #endif
            return -1;
        }
        return 0;
    }
    //
    if(proto<0 ||hdr->protocol == proto){
        ip_addr src = ntohl(hdr->saddr);
        ip_addr dst = ntohl(hdr->daddr);
        uint16_t identification = ntohs(hdr->id);
        #ifdef __IP_TEST_
        printIPHeader(hdr);
        #endif
        if(target){
            bool PacketSeen = checkAndSearchRecord(src,dst,hdr->protocol,identification);
            if(PacketSeen){
                #ifdef __IP_TEST_
                std::cerr<<"Seen IP packet from "<<ip2string(src)<<" to "
                <<ip2string(dst)<<" received."<<std::endl;
                #endif
                return -1;
            }
            else
            {
                addPacketRecord(src,dst,hdr->protocol,identification);
                #ifdef __IP_TEST_
                std::cout<<"IP packet from "<<ip2string(src)<<" to "
                <<ip2string(dst)<<" received."<<std::endl;
                #endif
                char *b = (char*)packetPtr + sizeof(iphdr);
                size_t l = packetLen - sizeof(iphdr);
                core_data::get().runningTCP->TCPSegmentReceiveCallback(b,l,src,dst);
                return 0;
            }
        }
        else if(self_sent){
            #ifdef __IP_TEST_
            std::cerr<<"Self sent packet ignored!"<<std::endl;
            #endif
            return -1;
        }
        else{
            if (hdr->ttl == 0){
                #ifdef __IP_TEST_
                std::cerr<<"TTL is now 0!"<<std::endl;
                #endif
                return -1;
            }
            else
            {
                //check whether packet seen 
                //std::cout<<"Record check fault?"<<std::endl;
                bool PacketSeen = checkAndSearchRecord(src,dst,hdr->protocol,identification);
                
                if(PacketSeen){
                    #ifdef __IP_TEST_
                    std::cerr<<"IP packet from "<<ip2string(src)<<" to "
                    <<ip2string(dst)<<" seen previously!"<<std::endl;
                    #endif
                    return -1;
                }
                else{
                    //std::cout<<"Record add fault?"<<std::endl;
                    addPacketRecord(src,dst,hdr->protocol,identification);
                    auto packetData = ((uint8_t*)packetPtr)+sizeof(iphdr);
                    auto packet_len = packetLen - sizeof(iphdr);
                    uint16_t f_and_o = ntohs(hdr->frag_off);
                    uint8_t flag = (f_and_o>>13)&(0x3);
                    uint16_t offset = (f_and_o)&(0x1FFF);
                    //std::cout<<"Send packet fault?"<<std::endl;
                    sendIPPacket(src, dst, hdr->protocol, hdr->tos, identification ,flag, offset ,hdr->ttl-1,packetData, packet_len);
                    #ifdef __IP_TEST_
                    std::cout<<"IP packet from "<<ip2string(src)<<" to "
                    <<ip2string(dst)<<" received."<<std::endl;
                    #endif
                    return 0;
                }
            }
        }
    }
    else
    {
        #ifdef __IP_TEST_
        printIPHeader(hdr);
        std::cerr<<"Protocol not matched!"<<std::endl;
        #endif
        return -1;
    }
    
}

int sendIPPacket(const ip_addr src, const ip_addr dest, uint8_t proto,  uint8_t typeOfService, uint16_t identification, uint8_t flag, uint16_t offset,uint8_t ttl, const void *buf, int len){
    bool local = 0;
    if(src == 0) local = 1;
    else
    {
        for(const auto &dev : core_data::get().devices){
            for (const auto &ip : dev->ip_addrs){
                if(src == ip) local = 1;
            }
        }
    }
    struct route_item *item;
    bool broadcast;
    //std::cout<<"Retrieve fault?"<<std::endl;
    bool retrieveflag = retrieveRouteItem(dest, &item , &broadcast);
    int deviceID;
    broadcast = broadcast | (dest == ip::IP_BROADCAST);
    //std::cout<<"Down ->"<<std::endl;
    if(broadcast == 0){
        if(!item){
            std::cerr<<"No route item for destination IP "<<ip2string(dest)<<" trying to broadcast"<<std::endl;
            broadcast = 1;
            //Determine whether or not send routing requests?
            //To do.
            std::cerr<<"First trying to build up routing table"<<std::endl;
            std::lock_guard<std::mutex> lk3(mutexSetupClock);
            if(setupClock == 0){
                for (int i = 0; i < core_data::get().devices.size(); ++i){setup(i);}
                setupClock = TIMEOUT;
            }
            else {setupClock--;}
        }
        else
        {
            deviceID = item->dev_id;
        }
    }
    //std::cout<<"Build packet fault?"<<std::endl;
    int packetLen = sizeof(iphdr) + len;
    auto packetPtr = (uint8_t *)malloc(packetLen);
    iphdr* hdr = (iphdr*)packetPtr;
    auto packetData = ((uint8_t*)packetPtr)+sizeof(iphdr);
    hdr->ihl = 5;
    hdr->version = 4;
    hdr->tos = typeOfService;
    hdr->tot_len = htons(packetLen);
    hdr->id = htons(identification);
    uint16_t f_and_o = ((flag&(0x3))<<13)|(offset&(0x1FFF));
    hdr->frag_off = htons(f_and_o);
    hdr->ttl = ttl;
    hdr->protocol = proto;
    hdr->saddr = htonl(src);
    hdr->daddr = htonl(dest);
    hdr->check = 0;
    hdr->check = ip_checksum(hdr, sizeof(iphdr));
    memcpy(packetData, buf, len);
    //std::cout<<"Send packet fault?"<<std::endl;
    if(broadcast){
        if(local){
            if(!src){
                for (int i = 0; i < core_data::get().devices.size(); ++i) {
                  uint8_t *dev_buf_ptr = (uint8_t *)malloc(packetLen);
                  memcpy(dev_buf_ptr, packetPtr, packetLen);
                  auto hdr = (iphdr *)dev_buf_ptr;
                  hdr->saddr = htonl(device::get_device_handler(i).ip_addrs[0]);
                  hdr->check = 0;
                  hdr->check = ip_checksum(hdr, sizeof(iphdr));
                  ethernet::sendFrame(dev_buf_ptr, packetLen, ip::ethertype, ethernet::ETHERNET_BROADCAST, i);
                  free(dev_buf_ptr);
                }
                free(packetPtr);
            }
            else
            {
                int id;
                for(int i = 0; i < core_data::get().devices.size(); ++i){
                    for (const auto &ip : device::get_device_handler(i).ip_addrs){
                        if(src == ip) id = i;
                    }
                }
                ethernet::sendFrame(packetPtr, packetLen, ip::ethertype, ethernet::ETHERNET_BROADCAST, id);
                free(packetPtr);
            }           
        }
        else
        {
            std::cerr<<"Broadcast repeated"<<std::endl;
            for (int i = 0; i < core_data::get().devices.size(); ++i) {
                ethernet::sendFrame(packetPtr, packetLen, ip::ethertype, ethernet::ETHERNET_BROADCAST, i);
            }
            free(packetPtr);
        }     
    }
    else
    {
        //If the packet has been seen, discard it.
        //Done in read handler.
        #ifdef __IP_TEST_
        std::cout<<"Normal send and Mac address: "<<ethernet::mac2string(item->mac_addr)<<" Id: "<<(unsigned)ntohs(hdr->id)<<std::endl;
        for (auto &item : routingTable){
            std::cout<<"Device ID "<<item.dev_id<<" |Dst "<<ip2string(item.dst)<<" |Mask "<<ip2string(item.mask)<<
            " |MAC address "<<ethernet::mac2string(item.mac_addr)<<std::endl;
        }
        #endif
        ethernet::sendFrame(packetPtr, packetLen, ip::ethertype, item->mac_addr, deviceID);
        //std::cout<<"packet free bug?"<<std::endl;
        free(packetPtr);
    }
    return 0;
}

bool retrieveRouteItem(const ip_addr dest,struct route_item **rt, bool *broadcast){
    //std::cout<<"lookup fault?"<<std::endl;
    bool find_item = lookup_route(dest,rt);
    if (!find_item){
        *rt = nullptr;
    }
    if(find_item&&((*rt)->exist==0)){
        uint32_t subnet_mask = (*rt)->prefix == 0 ? 0: (IP_BROADCAST<< (32 - (*rt)->prefix));
        *broadcast = ((dest | subnet_mask) == IP_BROADCAST);
    }
    else *broadcast = 0;
    //std::cout<<"decrease fault?"<<std::endl;
    decrease_age();
    //std::cout<<"up <-"<<std::endl;
    return find_item;
}
bool lookup_route(const ip_addr dest, struct route_item** savedItem){
    uint8_t max_prefix = 0;
    bool found = 0;
    std::lock_guard<std::mutex> lk(mutexRoutingTable);
    for(auto &item : routingTable){
        if (!item.prefix || dest >> (32 - item.prefix) == (item.dst) >> (32 - item.prefix)) {
            if(item.prefix >= max_prefix){
                *savedItem = &item;
                max_prefix = item.prefix;
                found = 1;
            }
        }
    }
    return found;
}

int setRoutingTable(const ip_addr dest, const ip_addr mask, const void* nextHopMAC, const char *device_name){
    int dev_id = device::findDevice(device_name);
    auto &d = device::get_device_handler(dev_id);
    bool has_router = 1;
    for (auto &ip : d.ip_addrs){
        if(dest == ip) has_router = 0;
    } 

    bool haveItem = 0;
    std::lock_guard<std::mutex> lk(mutexRoutingTable);
    for(auto &item : routingTable){
        if(item.dst == dest && item.mask == mask){
            haveItem = 1;
            item.dev_id = dev_id;
            item.exist = has_router;
            memcpy(item.mac_addr, nextHopMAC,sizeof(ethernet::mac_addr));
            item.age = ip::TIMEOUT;
            break;
        }
    }
    if(!haveItem){
        struct route_item rt;
        rt.dev_id = dev_id;
        rt.dst = dest;
        rt.exist = has_router;
        memcpy(rt.mac_addr, nextHopMAC,sizeof(ethernet::mac_addr));
        rt.mask = mask;
        rt.prefix = mask2prefix(mask);
        rt.age = ip::TIMEOUT;
        routingTable.emplace_back(rt);
    }
    return 0;
}

int setIPPacketReceiveCallback(IPPacketReceiveCallback callback){
    core_data::get().ip_callback = callback;
    return 0;
}

void setup(int dev_id){
    srand((unsigned)time(NULL));
    int setupPacketLen = sizeof(iphdr);
    auto setupPacketPtr = (uint8_t *)malloc(setupPacketLen);
    iphdr *hdr = (iphdr*)setupPacketPtr;
    hdr->ihl = 5;
    hdr->version = 4;
    hdr->tos = 0;
    hdr->tot_len = htons(setupPacketLen); 
    hdr->frag_off = 0x0040;
    hdr->ttl = 15;
    hdr->protocol = MY_ROUTING_PROTO;
    hdr->check = 0;
    auto &d = device::get_device_handler(dev_id);
    for (auto &ip : d.ip_addrs){
        hdr->saddr = htonl(ip);
        hdr->daddr = htonl(ip::IP_BROADCAST);
        hdr->id = rand() & 0xFFFF;
        hdr->check = ip_checksum(hdr, sizeof(iphdr));
        ethernet::sendFrame(setupPacketPtr, setupPacketLen, ip::ethertype, ethernet::ETHERNET_BROADCAST, dev_id);
    }
    free(setupPacketPtr);
}

uint8_t mask2prefix(const ip_addr x) {
  uint8_t count = 0;
  ip_addr n = x;
  while (n) {
    count += n & 1;
    n = (n >> 1);
  }
  return count;
}

ip_addr cidr_to_mask(uint8_t prefix) {
    return ((prefix == 0) ? 0 : (0xffffffff << (32 - prefix)));
}

void decrease_age(){
    std::lock_guard<std::mutex> lk(mutexRoutingTable);
	for (std::vector<struct route_item>::iterator item = routingTable.begin(); item != routingTable.end();)
	{
		if (item->age == 0)
			item = routingTable.erase(item);
		else
			--(item++)->age;
	}
}

bool route_item::operator==(const struct route_item &a) const{
    return (dev_id == a.dev_id)&&(exist == a.exist) && (dst == a.dst)
    &&(mask == a.mask) && (prefix == a.prefix) &&(!memcmp(mac_addr, a.mac_addr, sizeof(ethernet::mac_addr)));
}
bool flooding_record::operator<(const struct flooding_record &f)const {
    if(src != f.src){ return (src < f.src); }
    else
    {
        if(dst != f.dst) return (dst<f.dst);
        else
        {
            if(proto != f.proto ) return (proto<f.proto);
            else
            {
                return (id< f.id);
            }
        }
    }
}
bool checkAndSearchRecord(ip_addr srcIP, ip_addr dstIP, uint8_t proto, uint16_t id){
    struct flooding_record temp;
    temp.id = id;
    temp.src = srcIP;
    temp.dst = dstIP;
    temp.proto = proto;
    bool ret = 0 ;
    std::lock_guard<std::mutex> lk1(mutexRecordMap);
    if(record_map.count(temp)) ret = 1;
    else ret = 0;
    //If size greater than the maximum delete half.
    if(record_map.size()>=MAX_RECORD_NUM){
        int count = 0;
        for(std::map<struct flooding_record, int>::iterator item = record_map.begin(); item != record_map.end();){
            record_map.erase(item++);
            count++;
            if(count == MAX_RECORD_NUM/2){
                break;
            }
        }
    }
    return ret;
}
bool addPacketRecord(ip_addr srcIP,ip_addr dstIP, uint8_t proto, uint16_t id){
    struct flooding_record temp;
    temp.id = id;
    temp.src = srcIP;
    temp.dst = dstIP;
    temp.proto = proto;
    std::lock_guard<std::mutex> lk1(mutexRecordMap);
    std::pair<std::map<struct flooding_record,int>::iterator,bool> InsertPair; 
    InsertPair = record_map.insert(std::pair<struct flooding_record, int>(temp,1));
    return InsertPair.second;
}

uint16_t ip_checksum(const void *vdata, size_t length) {
  // Cast the data pointer to one that can be indexed.
  char *data = (char *)vdata;

  // Initialise the accumulator.
  uint64_t acc = 0xffff;

  // Handle any partial block at the start of the data.
  unsigned int offset = ((uintptr_t)data) & 3;
  if (offset) {
    size_t count = 4 - offset;
    if (count > length)
      count = length;
    uint32_t word = 0;
    memcpy(offset + (char *)&word, data, count);
    acc += ntohl(word);
    data += count;
    length -= count;
  }
    // Handle any complete 32-bit blocks.
  char *data_end = data + (length & ~3);
  while (data != data_end) {
    uint32_t word;
    memcpy(&word, data, 4);
    acc += ntohl(word);
    data += 4;
  }
  length &= 3;

  // Handle any partial block at the end of the data.
  if (length) {
    uint32_t word = 0;
    memcpy(&word, data, length);
    acc += ntohl(word);
  }

  // Handle deferred carries.
  acc = (acc & 0xffffffff) + (acc >> 32);
  while (acc >> 16) {
    acc = (acc & 0xffff) + (acc >> 16);
  }

  // If the data began at an odd byte address
  // then reverse the byte order to compensate.
  if (offset & 1) {
    acc = ((acc & 0xff00) >> 8) | ((acc & 0x00ff) << 8);
  }

  // Return the checksum in network byte order.
  return htons(~acc);
}

void printIPHeader(const void* packetPtr){
    iphdr *hdr = (iphdr*)packetPtr;
    ip_addr src = ntohl(hdr->saddr);
    ip_addr dst = ntohl(hdr->daddr);
    uint8_t tos = hdr->tos;
    uint16_t tot_len = ntohs(hdr->tot_len);
    uint16_t frag_off = ntohs(hdr->frag_off);
    uint8_t ttl = hdr->ttl;
    uint8_t proto = hdr->protocol;
    uint16_t check = hdr->check;
    uint16_t identification = ntohs(hdr->id);
    std::cout<<"Src IP address: "<<ip2string(src)
    <<" Dst IP address: "<<ip2string(dst)
    <<" ToS "<<(unsigned)tos
    <<" Total length "<<(unsigned)tot_len
    <<" Identification "<<(unsigned)identification
    <<" Frag and Off "<<(unsigned)frag_off
    <<" TTL "<<(unsigned)ttl
    <<" Protocol "<<(unsigned)proto
    <<" Checksum "<<(unsigned)check<<" IP packet finished!"<<std::endl;

}

}
}