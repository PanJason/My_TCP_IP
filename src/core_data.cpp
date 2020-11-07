#include "device.h"
#include "packetio.h"
#include "core_data.h"
#include <vector>
#include <future>
#include <thread>

namespace pan_protocol_stack{
namespace core_data{
    static core my_core;
    core &get(){
        return my_core;
    }
}
}