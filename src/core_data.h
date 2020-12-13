#ifndef  __CORE_H_
#define  __CORE_H_


#include "device.h"
#include "ip.h"
#include "socket.h"

#include <vector>
#include <future>
#include <thread>

namespace pan_protocol_stack{
namespace core_data{
    struct core{
        std::vector<std::shared_ptr<device::device_t> > devices;
        tcp::TCP_stack* runningTCP = nullptr;
        ethernet::frameReceiveCallback ethernet_callback;
        ip::IPPacketReceiveCallback ip_callback;
    };
    core &get();
}
}

#endif