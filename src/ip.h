#ifndef __IP_H_
#define __IP_H_
#include <vector>
#include <netinet/ip.h>
#include <string>


namespace pan_protocol_stack{
namespace ip{

using ip_addr = uint32_t;
static const uint16_t ethertype = 0x0800;
static const uint32_t IP_BROADCAST = 0xFFFFFFFF;
static const uint8_t MY_ROUTING_PROTO = 253;
static const int TIMEOUT = 2000;

std::string ip2string(const ip_addr &ip); 

struct flooding_record{
    ip_addr src;
    ip_addr dst;
    uint8_t proto;
    uint16_t id;
    bool operator<(const struct flooding_record &f) const;
};
static const int MAX_RECORD_NUM = 65536;
/**
 * One of the items in the routing table.
 */
struct route_item{
    int dev_id = -1;
    bool exist;
    ip_addr dst;
    ip_addr mask;
    uint8_t mac_addr[6];
    uint8_t prefix;
    int age = 0;
    bool operator==(const struct route_item &a) const;
};
/**
 * @brief Get the current routing table.
 * 
 * @return std::vector<struct route_item>& the current routing table
 */
std::vector<struct route_item> &getRoutingTable();

/**
 * @brief Get the route_item corresponding to the given ip address
 * 
 * @param dest the given ip address of destination
 * @param rt the pointer to the pointer to the route_item
 * @param broadcast the pointer to the bool value to determine whether a broadcast address.
 * @return 1 on success, 0 otherwise
 */
bool retrieveRouteItem(const ip_addr dest, route_item **rt, bool *broadcast);


/**
 * @brief Manully add an item to routing table. Useful when talking with real 
 * Linux machines.
 * 
 * @param dest The destination IP prefix.
 * @param mask The subnet mask of the destination IP prefix.
 * @param nextHopMAC MAC address of the next hop.
 * @param device Name of device to send packets on.
 * @return 0 on success, -1 on error
 */
int setRoutingTable(const ip_addr dest, const ip_addr mask, 
    const void* nextHopMAC, const char *device_name);

/**
 * @brief search the given ip addr in the current routing table and save the answer 
 * in the given pointer.
 * 
 * @param dest destination ip address
 * @param savedItem a pointer to the pointer to the result item.
 * @param mask The subnet mask of the destination IP prefix
 * @return 1 on success, 0 otherwise
 */
bool lookup_route(const ip_addr dest, struct route_item** savedItem);

/**
 * @brief setup the routing table
 * @return 
 */
void setup(int dev_id);


/**
 * @brief Send an IP packet to specified host. 
 *
 * @param src Source IP address.
 * @param dest Destination IP address.
 * @param proto Value of `protocol` field in IP header.
 * @param buf pointer to IP payload
 * @param len Length of IP payload
 * @return 0 on success, -1 on error.
 */
int sendIPPacket(const ip_addr src, const ip_addr dest, 
    uint8_t proto, uint8_t typeOfService, uint16_t identification, uint8_t flag, uint16_t offset, uint8_t ttl, const void *buf, int len);


/** 
 * @brief Process an IP packet upon receiving it.
 *
 * @param buf Pointer to the packet.
 * @param len Length of the packet.
 * @return 0 on success, -1 on error.
 * @see addDevice
 */
using IPPacketReceiveCallback = int (*)(const void * packetPtr, int packetLen,int dev_id, int proto, const void *src_mac);

/**
 * @brief Register a callback function to be called each time an IP packet
 * was received.
 *
 * @param callback The callback function.
 * @return 0 on success, -1 on error.
 * @see IPPacketReceiveCallback
 */
int setIPPacketReceiveCallback(IPPacketReceiveCallback callback);

/**
 * @brief the default handler when receiving an IP packet
 * 
 * @param ethertype in the type of the ethernet packet
 * @param packetPtr the pointer to the content in the ethernet packet.
 * @param packetLen the length of the content
 * @param dev_id the device id
 * @return 1 on success 0 otherwise.
 */
int defaultIPPacketHandler(const void * packetPtr, int packetLen,int dev_id, int proto, const void *src_mac);

uint8_t mask2prefix(const ip_addr mask);
ip_addr cidr_to_mask(const uint8_t prefix);
void decrease_age();
bool checkAndSearchRecord(ip_addr srcIP,ip_addr dstIP, uint8_t proto, uint16_t id);
bool addPacketRecord(ip_addr srcIP,ip_addr dstIP, uint8_t proto, uint16_t id);
uint16_t ip_checksum(const void *vdata, size_t length);
void printIPHeader(const void* packetPtr);
}
}
#endif