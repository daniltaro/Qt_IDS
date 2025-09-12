#include "ipv4header.h"
#include <iostream>

void Ipv4Header::printIPv4Header() const {
    const u_char version = versionIHL >> 4;
    const u_char ihl = versionIHL & 0x0F;
    std::cout << "version - " << static_cast<int>(version) << std::endl;
    std::cout << "header Length - " << static_cast<int>(ihl) * 4 << " bytes" << std::endl;
    std::cout << "total Length: " << ntohs(totalLength) << " bytes" << std::endl;

    const u_char frags = ntohs(fragOffset) >> 13;
    const uint16_t offset = ntohs(fragOffset) & 0x1FFF;

    std::cout << "frags - " << static_cast<int>(frags) << std::endl;
    std::cout << "fragment offset - " << static_cast<int>(offset) << std::endl;

    std::cout << "ipv4 source ip - ";
    for (int i = 0; i < 4; i++) {
        printf("%d", srcIP[i]);
        if (i < 3) {
            printf(".");
        }
    }
    printf("\n");

    std::cout << "ipv4 dst ip - ";
    for (int i = 0; i < 4; i++) {
        printf("%d", dstIP[i]);
        if (i < 3) printf(".");
    }
    printf("\n");

    std::cout << "ip protocol - ";
    switch (protocol) {
    case 1: std::cout << "ICMP\n";
        break;
    case 2: std::cout << "IGMP\n";
        break;
    case 3: std::cout << "GGP\n";
        break;
    case 4: std::cout << "ST\n";
        break;
    case 6: std::cout << "TCP\n";
        break;
    case 8: std::cout << "EGP\n";
        break;
    case 9: std::cout << "IGP\n";
        break;
    case 17: std::cout << "UDP\n";
        break;
    default: std::cout << "Unknown protocol type\n";
        break;
    }

    std::cout << "ttl - ";
    printf("%d\n", ttl);
}

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
