#include "ipv4header.h"

u_char Ipv4Header::protocolType() const {
    return protocol;
}

u_char Ipv4Header::versionIHLGet() const {
    return versionIHL;
}

std::string Ipv4Header::getSrcIP() const {
    std::string ipStr = std::to_string(srcIP[0]) + "." +
                        std::to_string(srcIP[1]) + "." +
                        std::to_string(srcIP[2]) + "." +
                        std::to_string(srcIP[3]);

    return ipStr;
}

std::string Ipv4Header::getDstIP() const {
    std::string ipStr = std::to_string(dstIP[0]) + "." +
                        std::to_string(dstIP[1]) + "." +
                        std::to_string(dstIP[2]) + "." +
                        std::to_string(dstIP[3]);

    return ipStr;
}
