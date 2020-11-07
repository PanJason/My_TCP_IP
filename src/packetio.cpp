#include "core_data.h"
#include <cstring>
#include <netinet/if_ether.h>
#include <iostream>
#include <stdlib.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <string>
#include <iomanip>


namespace pan_protocol_stack {
namespace ethernet {

	int setFrameReceiveCallback(ethernet::frameReceiveCallback callback) {
		core_data::get().ethernet_callback = callback;
	}

	int sendFrame(const void* buf, int len, int ethtype, const void* destmac, int id) {
		auto &device = device::get_device_handler(id);
		int frame_len = ETH_HEADER_LEN + len + CRC_LEN;
		uint8_t* frame_buf = new uint8_t[frame_len];
		auto eptr = (struct ether_header*)frame_buf;
		memcpy(eptr->ether_dhost, destmac, MAC_LEN);
		memcpy(eptr->ether_shost, device.mac_address, MAC_LEN);
		frame_buf[2 * MAC_LEN] = (ethtype >> 8) & 0xFF;
		frame_buf[2 * MAC_LEN + 1] = ethtype & 0xFF;
		memcpy(frame_buf + ETH_HEADER_LEN, buf, len);
		if (pcap_sendpacket(device.pcap_handler, frame_buf, frame_len) != 0) {
			return -1;
		}
		return 0;
	}

	int print_callback(const void* frame, int len, int dev_id){
		auto eptr = (struct ether_header*)frame;
		u_char *ptr;
		int i;
		/*See http://yuba.stanford.edu/~casado/pcap/section2.html */
		/* Do a couple of checks to see what packet type we have..*/
		if (ntohs (eptr->ether_type) == ETHERTYPE_IP)
		{
			fprintf(stdout,"Ethernet type hex:%x dec:%d is an IP packet\n",
					ntohs(eptr->ether_type),
					ntohs(eptr->ether_type));
		}else  if (ntohs (eptr->ether_type) == ETHERTYPE_ARP)
		{
			fprintf(stdout,"Ethernet type hex:%x dec:%d is an ARP packet\n",
					ntohs(eptr->ether_type),
					ntohs(eptr->ether_type));
		}else {
			fprintf(stdout, "Ethernet type %x not IP", ntohs(eptr->ether_type));
			return -1;
		}

		/* copied from Steven's UNP */
		ptr = eptr->ether_dhost;
		i = ETHER_ADDR_LEN;
		fprintf(stdout," Destination Address:  ");
		do{
			fprintf(stdout, "%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
		}while(--i>0);
		fprintf(stdout, "\n");

		ptr = eptr->ether_shost;
		i = ETHER_ADDR_LEN;
		fprintf(stdout," Source Address:  ");
		do{
			fprintf(stdout,"%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
		}while(--i>0);
		fprintf(stdout,"\n");
		fflush(stdout);

		std::cout<<"On network device "<<device::get_device_handler(dev_id).device_name<<" ."<<std::endl;
		return 0;
	}

	int start_capturing(int dev_id){
		const u_char *packet;
    	struct pcap_pkthdr *hdr;
		device::device_t d = device::get_device_handler(dev_id);
		int res;
		std::cout<<"Capturing at Mac Address "<<mac2string(d.mac_address)<<std::endl;
		while((res = pcap_next_ex(d.pcap_handler, &hdr, &packet)) >=0 ){
			if(res == 0){
				std::cerr<<"Timeout!"<<std::endl;
			}
			int ret = core_data::get().ethernet_callback(packet, hdr->len,dev_id);
			if (ret<0) return -1;			
		}
		if (res<0) return -1;
		return 0;
	}

	std::string mac2string(const mac_addr addr){
		std::ostringstream os;
		for (int i = 0; i < 6; i++) {
			os << std::setfill('0') << std::hex << std::setw(2) << (int)addr[i];
			if (i < 5) {
			os << ":";
			}
		}
		return os.str();
	}
}
}