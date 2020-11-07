#ifndef __DEVICE_H_
#define __DEVICE_H_

#include "packetio.h"
#include <string>
#include <pcap/pcap.h>

namespace pan_protocol_stack{
namespace device{
	const size_t BUF_SIZE = 65536;
	const size_t TIMEOUT = 10;
struct device_t{
    std::string device_name;
	ethernet::mac_addr mac_address;
    int id;
    pcap_t* pcap_handler;
    device_t();
    ~device_t();
	int create_pcap_handler();

};
/**
 * Add a device to the library for sending/receiving packets. 
 *
 * @param device Name of network device to send/receive packet on.
 * @return A non-negative _device-ID_ on success, -1 on error.
 */
int addDevice(const char* device);
/**
 * Find a device added by `addDevice`.
 *
 * @param device Name of the network device.
 * @return A non-negative _device-ID_ on success, -1 if no such device 
 * was found.
 */
int findDevice(const char* device);
/**
 * Get the device handler
 * 
 * @param device id
 * @return a reference to that device handler
 */
device_t& get_device_handler(int id);
}
}

#endif