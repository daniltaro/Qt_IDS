#include "udpheader.h"

uint16_t UDPHeader::getSrcPort() const {
    return ntohs(srcPort);
}

uint16_t UDPHeader::getDstPort() const {
    return ntohs(dstPort);
}
