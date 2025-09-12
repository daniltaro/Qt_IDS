#include "icmpheader.h"
#include <iostream>

void ICMPHeader::printICMPHeader() const {
    std::cout << "type - ";
    if (type == 8) std::cout << "echo request\n";
    else if (type == 0) std::cout << "echo reply\n";
    else if (type == 3) std::cout << "destination unreachable\n";
    else if (type == 5) std::cout << "redirect message\n";
    else if (type == 11) std::cout << "time exceeded\n";
    else std::cout << "unknown type\n";
    std::cout << "code - ";
    printf("%d\n", code);
}

u_char ICMPHeader::getType() const {
    return type;
}

u_char ICMPHeader::getCode() const {
    return code;
}
