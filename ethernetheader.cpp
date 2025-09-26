#include "ethernetheader.h"

uint16_t EthernetHeader::type() const {
    return ntohs(etherType);
}
