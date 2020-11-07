#ifndef  __CORE_H_
#define  __CORE_H_


#include "device.h"

#include <vector>
#include <future>
#include <thread>

namespace pan_protocol_stack{
namespace core_data{
    struct core{
        std::vector<std::shared_ptr<device::device_t> > devices;
        ethernet::frameReceiveCallback ethernet_callback;
    };
    core &get();
}
}

#endif