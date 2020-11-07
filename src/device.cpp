#include "core_data.h"
#include <sys/types.h>
#include <ifaddrs.h>
#include <cstring>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <pcap/pcap.h>
#include <iostream>


namespace pan_protocol_stack{
namespace device{
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
		//fprintf(stderr, "Fail to detect any devices!");
		return -1;
	}
	int ret_val = -1;
	for (ifaddrs *ifa = iaddrp; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;
		//std::cout<<std::string(ifa->ifa_name)<<std::endl;
		if ((!device && strcmp(ifa->ifa_name, "lo")) || (device && strcmp(ifa->ifa_name, device) == 0)) {
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
				}
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