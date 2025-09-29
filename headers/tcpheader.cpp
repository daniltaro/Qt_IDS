#include "tcpheader.h"

u_char TCPHeader::dataOffsetReservedGet() const {
    return dataOffsetReserved;
}

uint16_t TCPHeader::getSrcPort() const {
    return ntohs(srcPort);
}

uint16_t TCPHeader::getDstPort() const {
    return ntohs(dstPort);
}

u_char TCPHeader::getFlag() const{
    return flag;
}
