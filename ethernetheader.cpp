#include "ethernetheader.h"
#include <iostream>

void EthernetHeader::printMAC(const u_char *mac) const {
    for (int i = 0; i < 6; i++) {
        printf("%02x", mac[i]);
        if (i < 5) printf(":");
    }
    printf("\n");
}

void EthernetHeader::printEthernetHeader() const {
    std::cout << "source mac - ";
    printMAC(srcMAC);
    std::cout << "dest mac - ";
    printMAC(destMAC);
    std::cout << "ether type - ";
    printf("0x%04x\n", ntohs(etherType));
}

uint16_t EthernetHeader::type() const {
    return ntohs(etherType);
}
