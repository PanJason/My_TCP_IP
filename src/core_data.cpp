#include "device.h"
#include "packetio.h"
#include "core_data.h"
#include "ip.h"
#include <vector>
#include <future>
#include <thread>
#include <mutex>

namespace pan_protocol_stack{
namespace core_data{
std::mutex mutexDevice;
    static core my_core;
    core &get(){
        return my_core;
    }
}
}