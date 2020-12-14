#ifndef __ETH_H_
#define __ETH_H_

#include <stdint.h>
#include <netinet/ether.h>
#include <sys/types.h>
#include <pcap/pcap.h>
#include <string>

namespace pan_protocol_stack {
	namespace ethernet {
		const int CRC_LEN = 4;
		const int ETH_HEADER_LEN = 6 + 6 + 2;
		const int MAC_LEN = 6;

		using mac_addr = uint8_t[6];
		static const mac_addr ETHERNET_BROADCAST = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
		/**
		* @brief Encapsulate some data into an Ethernet II frame and send it.
		*
		* @param buf Pointer to the payload.
		* @param len Length of the payload.
		* @param ethtype EtherType field value of this frame.
		* @param destmac MAC address of the destination.
		* @param id ID of the device(returned by `addDevice`) to send on.
		* @return 0 on success, -1 on error.
		* @see addDevice
		*/
		int sendFrame(const void* buf, int len, int ethtype, const void* destmac, int id);

		/**
		* @brief Process a frame upon receiving it.
		*
		* @param buf Pointer to the frame.
		* @param len Length of the frame.
		* @param id ID of the device (returned by `addDevice`) receiving current
		* frame.
		* @return 0 on success, -1 on error.
		* @see addDevice
		*/
		using frameReceiveCallback = int(*)(const void*, int, int);

		/**
		* @brief Register a callback function to be called each time an Ethernet II
		* frame was received.
		*
		* @param callback the callback function.
		* @return 0 on success, -1 on error.
		* @see frameReceiveCallback
		*/
		int setFrameReceiveCallback(frameReceiveCallback callback);
		
		/**
		 * @brief A simple callback function to print out the ethernet packet.
		 * 
		 * @param buf Pointer to the frame
		 * @Param len Length of the frame
		 * @Param id ID of the device (returned by `addDevice`) receiving current 
		 * frame
		 * @return 0 on success, -1 on error.
		 */
		int print_callback(const void* frame, int len, int dev_id);

		/**
		 * @brief Start capturing packets on the device which has the given device ID.
		 * 
		 * @param id ID of the device capturing the frame.
		 * @return 0 on success, -1 on error.
		 */
		int start_capturing(int dev_id); 
		
		/**
		 * @brief convert ethernet::mac_addr to string
		 * 
		 * @param mac MAC address
		 * @return MAC address in string format.
		 */
		std::string mac2string(const mac_addr addr);

		int ether_broker_callback(const void* frame, int len, int dev_id);
	}
}

#endif