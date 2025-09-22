#include <iostream>
#include <fstream>
#include <chrono>
#include <nlohmann/json.hpp>
#include <thread>
#include <QDebug>

#include "loopbackhandler.h"
#include "ethernetheader.h"
#include "ipv4header.h"
#include "tcpheader.h"
#include "udpheader.h"
#include "icmpheader.h"

#define LINK_OFFSET 4

using json = nlohmann::json;
extern std::string save_buf;
LoopBackHandler::LoopBackHandler( bool all,  bool tcp,
                                 bool udp,  bool icmp) {
    all_packets = all;
    tcp_prot = tcp;
    udp_prot = udp;
    icmp_prot = icmp;
}

void LoopBackHandler::printPayload(const u_char *payload, const uint32_t &len) const {
    int offset = 0;

    for (int i = 0; i < len; i += 16) {
        std::cout << "0x" << std::hex << offset << ": ";

        for (int j = 0; j < 16; ++j) {
            if (i + j < len) {
                printf("%02x ", payload[i + j]);
            } else {
                printf("   ");
            }
        }

        std::cout << " | ";
        for (int j = 0; j < 16; ++j) {
            if (i + j < len) {
                const u_char ch = payload[i + j];
                printf("%c", (ch >= 32 && ch <= 126) ? ch : '.');
            }
        }
        std::cout << '\n';

        offset += 16;
    }
}

void LoopBackHandler::Handle(u_char *user, const struct pcap_pkthdr *header,
                             const u_char *packet) {
    pack_count++;

    auto *ipv4Header = (Ipv4Header *) (packet + LINK_OFFSET);

    packData.srcDst = QString::fromStdString
        (ipv4Header->getSrcIP() + " -> " + ipv4Header->getDstIP());

    const u_char ihl = ipv4Header->versionIHLGet() & 0x0F;
    const uint16_t ipHeaderLength = ihl * 4;

    std::string type = "";
    bool show_packet = false;

    //checking for suspicious
    if((icmp_prot || all_packets) && ipv4Header->protocolType() == 1){
        protocolCounter[ICMP] += 1;
        ipv4Counter[ipv4Header->getSrcIP()]++;
        ipv4Counter[ipv4Header->getDstIP()]++;

        auto *icmpHeader = (ICMPHeader *) (packet + LINK_OFFSET + ipHeaderLength);

        if(icmpHeader->getType() == 8){
            threatDec.icmpTypeAdd();
        }

        if(threatDec.isSuspiciousICMP(type) == true){
            packData.type = QString::fromStdString(type);
            this->saveStatistic(user, header, packet, true, type);
            show_packet = true;
        } else {
            packData.type = "-";
            this->saveStatistic(user, header, packet, false, type);
        }

    } if((tcp_prot || all_packets) && ipv4Header->protocolType() == 6){
        protocolCounter[TCP] += 1;
        ipv4Counter[ipv4Header->getSrcIP()]++;
        ipv4Counter[ipv4Header->getDstIP()]++;

        auto *tcpHeader = (TCPHeader *) (packet + LINK_OFFSET + ipHeaderLength);

        threatDec.addIPv4srcDstTCP(ipv4Header->getSrcIP(), tcpHeader->getDstPort());

        if (tcpHeader->getFlag() & 0x02) threatDec.tcpSYNAdd();
        else if(tcpHeader->getFlag() & 0x10) threatDec.tcpACKAdd();

        if(threatDec.isSuspiciousTCP(type) == true){
            packData.type = QString::fromStdString(type);
            this->saveStatistic(user, header, packet, true, type);
            show_packet = true;
        } else {
            packData.type = "-";
            this->saveStatistic(user, header, packet, false, type);
        }

    } if((udp_prot || all_packets) && ipv4Header->protocolType() == 17){
        protocolCounter[UDP] += 1;
        ipv4Counter[ipv4Header->getSrcIP()]++;
        ipv4Counter[ipv4Header->getDstIP()]++;
        threatDec.udpAdd();

        auto *udpHeader = (UDPHeader *) (packet + LINK_OFFSET + ipHeaderLength);

        threatDec.addIPv4srcDstUDP(ipv4Header->getSrcIP(), udpHeader->getDstPort());

        if(threatDec.issuspiciousUDP(type) == true){
            packData.type = QString::fromStdString(type);
            this->saveStatistic(user, header, packet, true, type);
            show_packet = true;
        } else {
            packData.type = "-";
            this->saveStatistic(user, header, packet, false, type);
        }

    }

    if(show_packet == false) return;

    std::cout << "packet len - " << std::dec << header->caplen << "\n\n";
    std::cout << "IPV4 HEADER:"<< '\n';
    ipv4Header->printIPv4Header();

    //parse and output
    if (ipv4Header->protocolType() == 6) {
        packData.protocol = "TCP";
        qDebug() << "Emitting packet:" << packData.protocol << packData.srcDst;
        emit packetCaptured(packData);
        std::cout << '\n';
        auto *tcpHeader = (TCPHeader *) (packet + LINK_OFFSET + ipHeaderLength);
        std::cout << "TCP HEADER:"<< '\n';
        tcpHeader->printTCPHeader();
        const uint8_t dataOffset = (tcpHeader->dataOffsetReservedGet() >> 4) * 4;

        std::cout << '\n';
        const uint32_t payloadLength = header->caplen - (LINK_OFFSET + ipHeaderLength + dataOffset);
        if (payloadLength > 0) {
            std::cout << "payload length - " << static_cast<int>(payloadLength)
            << " bytes" << std::endl;
            std::cout << "PAYLOAD:"<< '\n';
        } else {
            std::cout << "no payload" << std::endl;
            std::cout << "\n[ " <<  threatDec.getThreatCount()
                      << " THREAT FOUND ]" << "\n";
            return;
        }

        const u_char *payload = packet + LINK_OFFSET + ipHeaderLength + dataOffset;
        printPayload(payload, payloadLength);
    } else if (ipv4Header->protocolType() == 17) {
        packData.protocol = "UDP";
        qDebug() << "Emitting packet:" << packData.protocol << packData.srcDst;
        emit packetCaptured(packData);
        std::cout << '\n';
        auto *udpHeader = (UDPHeader *) (packet + LINK_OFFSET + ipHeaderLength);
        std::cout << "UDP HEADER:"<< '\n';
        udpHeader->printUDPHeader();

        std::cout << '\n';
        const uint32_t payloadLength = header->caplen - (LINK_OFFSET + ipHeaderLength + 8);
        if (payloadLength > 0) {
            std::cout << "payload length - " << static_cast<int>(payloadLength)
            << " bytes" << std::endl;
            std::cout << "PAYLOAD:"<< '\n';
        } else {
            std::cout << "no payload" << std::endl;
            std::cout << "\n[ " << threatDec.getThreatCount()
                      << " THREAT FOUND ]" << "\n";
            return;
        }

        const u_char *payload = packet + LINK_OFFSET + ipHeaderLength + 8;
        printPayload(payload, payloadLength);
    } else if (ipv4Header->protocolType() == 1) {
        packData.protocol = "ICMP";
        qDebug() << "Emitting packet:" << packData.protocol << packData.srcDst;
        emit packetCaptured(packData);
        std::cout << '\n';
        auto *icmpHeader = (ICMPHeader *) (packet + LINK_OFFSET + ipHeaderLength);
        std::cout << "ICMP HEADER:"<< '\n';
        icmpHeader->printICMPHeader();

        if(icmpHeader->getType() == 8){
            threatDec.icmpTypeAdd();
        }

        int icmpLen = 8;
        if (icmpHeader->getType() == 5 || icmpHeader->getType() == 11) {
            switch (icmpHeader->getCode()) {
            case 3:
            case 11:
            case 12: icmpLen = 36;
                break;
            case 5: icmpLen = 12;
                break;
            case 13:
            case 14: icmpLen = 20;
                break;
            default: icmpLen = 8;
                break;
            }
        }

        std::cout << '\n';
        const uint32_t payloadLength = header->caplen - (LINK_OFFSET + ipHeaderLength + icmpLen);
        if (payloadLength > 0) {
            std::cout << "payload length - " << static_cast<int>(payloadLength)
            << " bytes" << std::endl;
            std::cout << "PAYLOAD:"<< '\n';
        } else {
            std::cout << "no payload" << std::endl;
            std::cout << "\n[ " << threatDec.getThreatCount()
                      << " THREAT FOUND ]" << "\n";
            return;
        }

        const u_char *payload = packet + LINK_OFFSET + ipHeaderLength + icmpLen;
        printPayload(payload, payloadLength);
    }
    else{
        std::cout << "\nunknown IPV4 protocol\n";
    }
    std::cout << "\n[ " << threatDec.getThreatCount()
              << " THREAT FOUND ]" << "\n";
}

void LoopBackHandler::printStatistic() {
    std::cout << "------------------------------" << std::endl;
    std::cout << "TCP protocols - " << std::dec << protocolCounter[TCP] << std::endl;
    std::cout << "UDP protocols - " << std::dec << protocolCounter[UDP] << std::endl;
    std::cout << "ICMP protocols - " << std::dec << protocolCounter[ICMP] << std::endl;
    std::cout << "Threat count - " << std::dec << threatDec.getThreatCount()  << std::endl;
    std::cout << "Packets count - " << pack_count << std::endl;

    for (const auto &entry: ipv4Counter) {
        std::cout << entry.first << " - " << entry.second << std::endl;
    }
    std::cout << "------------------------------" << std::endl;
}

void LoopBackHandler::saveGenStatistic() {

    save_buf += "{\n";
    save_buf += "  \"TCP\": " + std::to_string(protocolCounter[TCP]) + ",\n";
    save_buf += "  \"UDP\": " + std::to_string(protocolCounter[UDP]) + ",\n";
    save_buf += "  \"ICMP\": " + std::to_string(protocolCounter[ICMP]) + ",\n";
    save_buf += "   \"IP_Stats\": {\n";

    bool first = true;
    for (const auto &entry: ipv4Counter) {
        if (!first) {
            save_buf +=",\n";
        }
        save_buf += "    \"" + entry.first + "\": " + std::to_string(entry.second);
        first = false;
    }
    save_buf += "\n  },\n";
    save_buf +="  \"timestamp\": \"";
    auto now = std::chrono::system_clock::now();
    auto time_point = std::chrono::system_clock::to_time_t(now);
    std::string time_str = std::ctime(&time_point);
    time_str.pop_back();
    save_buf += time_str +"\"\n";
    save_buf += "}\n";
}

void LoopBackHandler::saveStatistic(const struct pcap_pkthdr *header,
                                    const u_char *packet, bool flag, const std::string& type) const{

    json j;
    auto now = std::chrono::system_clock::now();
    auto time_point = std::chrono::system_clock::to_time_t(now);
    std::string time_str = std::ctime(&time_point);
    time_str.pop_back();
    j["timestamp"] = time_str;

    auto *ipv4Header = (Ipv4Header *) (packet + LINK_OFFSET);
    j["src_ip"] = ipv4Header->getSrcIP();
    j["dst_ip"] = ipv4Header->getDstIP();

    const u_char ihl = ipv4Header->versionIHLGet() & 0x0F;
    const uint16_t ipHeaderLength = ihl * 4;

    if (ipv4Header->protocolType() == 6){
        j["protocol"] = "TCP";
        auto *tcpHeader = (TCPHeader *) (packet + LINK_OFFSET + ipHeaderLength);
        j["src_port"] = tcpHeader->getSrcPort();
        j["dst_port"] = tcpHeader->getDstPort();
    }
    else if (ipv4Header->protocolType() == 17){
        j["protocol"] = "UDP";
        auto *udpHeader = (UDPHeader *) (packet + LINK_OFFSET + ipHeaderLength);
        j["src_port"] = udpHeader->getSrcPort();
        j["dst_port"] = udpHeader->getDstPort();
    }
    else if (ipv4Header->protocolType() == 1) j["protocol"] = "ICMP";

    j["length"] = header->caplen;
    j["threat"] = flag;
    if(flag) j["type"] = type;

    if(commaFlag) save_buf += ",\n";
    commaFlag = true;

    static std::mutex lock;
    std::lock_guard<std::mutex> lock_g(lock);
    save_buf += j.dump();
}

