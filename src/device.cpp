#include "core_data.h"
#include "ip.h"
#include <sys/types.h>
#include <ifaddrs.h>
#include <cstring>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <pcap/pcap.h>
#include <iostream>
#include <sys/epoll.h>
#include <mutex>
#include <map>


namespace pan_protocol_stack{
namespace device{

struct epoll_event global_events[256];
int global_epfd;
std::map<int,int> fd2id;
std::mutex mutexFd2id;

int epoll_init(){
	global_epfd = epoll_create(256);
	if(global_epfd == -1){
		std::cerr<<"epoll_create error"<<std::endl;
		return -1;
	}
	return 0;
}
int epoll_read(int timeout){
  int res;
  res = epoll_wait(global_epfd, global_events, 256, timeout);
  if (res < 0) {
    std::cerr << "epoll_wait failed"<<std::endl;
    return -1;
  }
  if (res == 0) {
    return -1;
  }
  for (int i = 0; i < res; i++) {
    int fd = global_events[i].data.fd;
    if (global_events[i].events & EPOLLERR) {
      std::cerr<<  "fd: " << fd << "read fail";
    }
  get_device_handler(fd2id[fd]).read();
  }
  return 1;
}
void epoll_server_init(){
	epoll_init();
	addDevice(nullptr);
	ethernet::setFrameReceiveCallback(ethernet::ether_broker_callback);
	ip::setIPPacketReceiveCallback(ip::defaultIPPacketHandler);
}
void epoll_server(int timeout){
	while (1)
	{
		epoll_read(timeout);
	}
	
}
int device_t::read(){
		const u_char *packet;
    	struct pcap_pkthdr *hdr;
		int res;
		while((res = pcap_next_ex(this->pcap_handler, &hdr, &packet)) >=0 ){
			if(res == 0){
				return 0;
			}
			return core_data::get().ethernet_callback(packet, hdr->len,this->id);	
		}
		return 0;
}
int device_t::create_pcap_handler() {
	char error_buffer[PCAP_ERRBUF_SIZE];
	pcap_handler = pcap_open_live(device_name.c_str(), BUF_SIZE, false, TIMEOUT, error_buffer);
	if (!pcap_handler || pcap_datalink(pcap_handler) != DLT_EN10MB)
		return -1;
	return 0;
}
device_t::device_t(){
}
device_t::~device_t() {
	if (pcap_handler) pcap_close(pcap_handler);
}

int findDevice(const char* device){
    for(int i = 0; i<core_data::get().devices.size();i++){
        if(core_data::get().devices[i]->device_name == device){
            return i;
        }
    }
    return -1;
}
int addDevice(const char* device){
	ifaddrs* iaddrp = nullptr;
	if (getifaddrs(&iaddrp) == -1) {
		fprintf(stderr, "Fail to detect any devices!");
		return -1;
	}
	int ret_val = -1;
	for (ifaddrs *ifa = iaddrp; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;
		//std::cout<<std::string(ifa->ifa_name)<<std::endl;
		if ((!device && (strcmp(ifa->ifa_name, "lo")&& strcmp(ifa->ifa_name, "sit0"))) || (device && strcmp(ifa->ifa_name, device) == 0)) {
			//fprintf(stderr,"We are adding devices now!");
			int family = ifa->ifa_addr->sa_family;
			if (family == AF_PACKET) {
				auto s = (sockaddr_ll*)(ifa->ifa_addr);
				auto new_device = std::make_shared<device_t>();
				
				new_device->device_name = std::string(ifa->ifa_name);
				memcpy(new_device->mac_address, s->sll_addr, sizeof(ethernet::mac_addr));
				new_device->id = core_data::get().devices.size();

				core_data::get().devices.push_back(new_device);
				if (new_device->create_pcap_handler() == 0) {
					ret_val = new_device->id;
					int pcap_fd = pcap_get_selectable_fd(new_device->pcap_handler);
					if(pcap_fd == PCAP_ERROR){std::cerr<<"pcap_get_selectable_fd failed"<<std::endl;}
					char error_buffer[PCAP_ERRBUF_SIZE];
					if (pcap_setnonblock(new_device->pcap_handler,1, error_buffer) < 0) {std::cerr<<"set nonblock error"<<std::endl;}
					struct epoll_event event;
					event.events = EPOLLIN ;
					event.data.fd = pcap_fd;
					int rv;
					rv = epoll_ctl(global_epfd, EPOLL_CTL_ADD, pcap_fd, &event);
					if(rv <0) std::cerr << "epoll add failed"<<std::endl; 
					fd2id[pcap_fd] = new_device->id;
				}
			}
			else if(family == AF_INET){
				auto s = (sockaddr_in *)ifa->ifa_addr;
				if (ret_val == -1) {
					continue;
				}
				int dev_id = findDevice(ifa->ifa_name);
				auto &d = get_device_handler(dev_id);
				uint32_t ip = ntohl(s->sin_addr.s_addr);
				d.ip_addrs.push_back(ip);
				//ip::setRoutingTable(ip, ntohl(((const struct sockaddr_in *)ifa->ifa_netmask)->sin_addr.s_addr),d.mac_address,ifa->ifa_name);
			}
		}
	}
	freeifaddrs(iaddrp);
	return ret_val;
}
device_t& get_device_handler(int id) {
	return *(core_data::get().devices.at(id));
}
}
}