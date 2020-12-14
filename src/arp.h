#ifndef __ARP_H_
#define __ARP_H_
#include "ip.h"
#include "packetio.h"
#include "device.h"
#include <map>
#include <utility>

namespace pan_protocol_stack{
namespace arp{

using arp_table = std::map<ip::ip_addr, std::pair<device::mac_wapper, int> >;

static const uint16_t ethertype = 0x0806;
static const int TIMEOUT = 20;

struct __attribute__((packed)) arp_header{
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_len;
    uint8_t protocol_len;
    uint16_t opcode;
    uint8_t sender_mac[6];
    ip::ip_addr sender_ip;
    uint8_t target_mac[6];
    ip::ip_addr target_ip;
};
/**
 * @brief the default handler when receiving an arp packet
 * 
 * @param ethertype in the type of the ethernet packet
 * @param packetPtr the pointer to the content in the ethernet packet.
 * @param packetLen the length of the content
 * @param dev_id the device id
 * @return 1 on success 0 otherwise.
 */
bool defaultARPPacketHandler(uint16_t ethertype, const void * packetPtr, int packetLen, int dev_id);
/**
 * @brief Send a ARP packet.
 * 
 * @param dev_id device id to send the ARP packet
 * @param opcode ARP opcode
 * @param sender_mac sender MAC address
 * @param sender_ip sender IP address
 * @param target_mac target mac address
 * @param target_ip target mac address
 * @return 0 on success -1 otherwise
 */
int sendARPPacket(int dev_id, uint16_t opcode, const ethernet::mac_addr sender_mac,
const ip::ip_addr sender_ip, const ethernet::mac_addr target_mac, const ip::ip_addr target_ip);
/**
 * @brief search mac address of the given ip destination
 * address in the arp table
 * 
 * @param dev_id the device IP
 * @dest the destination IP address
 * @return 1 on success, 0 otherwise
 */
bool search_arp(int dev_id, const ip::ip_addr dest, device::mac_wapper *result);

/**
 * @brief decrease the timeout in the arp_neighbour
 */
void decrease_time();
}
}
#endif