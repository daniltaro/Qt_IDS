#include "icmpheader.h"

u_char ICMPHeader::getType() const {
    return type;
}

u_char ICMPHeader::getCode() const {
    return code;
}
