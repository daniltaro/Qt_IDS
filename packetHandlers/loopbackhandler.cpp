#include <iostream>
#include <fstream>
#include <chrono>
#include <nlohmann/json.hpp>
#include <thread>
#include <QDebug>

#include "loopbackhandler.h"
#include "../headers/ipv4header.h"
#include "../headers/tcpheader.h"
#include "../headers/udpheader.h"
#include "../headers/icmpheader.h"

#define LINK_OFFSET 4

using json = nlohmann::json;
extern std::string save_buf;

void LoopBackHandler::Handle(const struct pcap_pkthdr *header,
                             const u_char *packet) {

    auto *ipv4Header = (Ipv4Header *) (packet + LINK_OFFSET);

    packData.srcDst = QString::fromStdString
        (ipv4Header->getSrcIP() + " -> " + ipv4Header->getDstIP());

    const u_char ihl = ipv4Header->versionIHLGet() & 0x0F;
    const uint16_t ipHeaderLength = ihl * 4;

    std::string type = "";
    bool show_packet = false;

    //checking for suspicious
    if((icmp_prot || all_packets) && ipv4Header->protocolType() == 1){
        show_packet = true;
        protocolCounter[ICMP] += 1;
        ipv4Counter[ipv4Header->getSrcIP()]++;
        ipv4Counter[ipv4Header->getDstIP()]++;

        auto *icmpHeader = (ICMPHeader *) (packet + LINK_OFFSET + ipHeaderLength);

        if(icmpHeader->getType() == 8){
            threatDec.icmpTypeAdd();
        }

        if(threatDec.isSuspiciousICMP(type) == true){
            packData.type = QString::fromStdString(type);
            this->saveJsonStatistic(header, packet, true, type);
        } else {
            packData.type = "-";
            this->saveJsonStatistic(header, packet, false, type);
        }

    } if((tcp_prot || all_packets) && ipv4Header->protocolType() == 6){
        show_packet = true;
        protocolCounter[TCP] += 1;
        ipv4Counter[ipv4Header->getSrcIP()]++;
        ipv4Counter[ipv4Header->getDstIP()]++;

        auto *tcpHeader = (TCPHeader *) (packet + LINK_OFFSET + ipHeaderLength);

        threatDec.addIPv4srcDstTCP(ipv4Header->getSrcIP(), tcpHeader->getDstPort());

        if (tcpHeader->getFlag() & 0x02) threatDec.tcpSYNAdd();
        else if(tcpHeader->getFlag() & 0x10) threatDec.tcpACKAdd();

        if(threatDec.isSuspiciousTCP(type) == true){
            packData.type = QString::fromStdString(type);
            this->saveJsonStatistic(header, packet, true, type);
        } else {
            packData.type = "-";
            this->saveJsonStatistic(header, packet, false, type);
        }

    } if((udp_prot || all_packets) && ipv4Header->protocolType() == 17){
        show_packet = true;
        protocolCounter[UDP] += 1;
        ipv4Counter[ipv4Header->getSrcIP()]++;
        ipv4Counter[ipv4Header->getDstIP()]++;
        threatDec.udpAdd();

        auto *udpHeader = (UDPHeader *) (packet + LINK_OFFSET + ipHeaderLength);

        threatDec.addIPv4srcDstUDP(ipv4Header->getSrcIP(), udpHeader->getDstPort());

        if(threatDec.issuspiciousUDP(type) == true){
            packData.type = QString::fromStdString(type);
            this->saveJsonStatistic(header, packet, true, type);
        } else {
            packData.type = "-";
            this->saveJsonStatistic(header, packet, false, type);
        }

    }

    if(show_packet == false) return;
    pack_count++;

    //parse and output
    if (ipv4Header->protocolType() == 6) {
        packData.protocol = "TCP";

        auto *tcpHeader = (TCPHeader *) (packet + LINK_OFFSET + ipHeaderLength);
        const uint8_t dataOffset = (tcpHeader->dataOffsetReservedGet() >> 4) * 4;

        const uint32_t payloadLength = header->caplen - (LINK_OFFSET + ipHeaderLength + dataOffset);
        const u_char *payload = packet + LINK_OFFSET + ipHeaderLength + dataOffset;
        if (payloadLength > 0){
            packData.hex = getPayload(payload, payloadLength);
        }
        else packData.hex = "no payload";
        emit packetCaptured(packData);
    } else if (ipv4Header->protocolType() == 17) {
        packData.protocol = "UDP";


        const uint32_t payloadLength = header->caplen - (LINK_OFFSET + ipHeaderLength + 8);
        const u_char *payload = packet + LINK_OFFSET + ipHeaderLength + 8;
        if (payloadLength > 0){
            packData.hex = getPayload(payload, payloadLength);
        }
        else packData.hex = "no payload";
        emit packetCaptured(packData);
    } else if (ipv4Header->protocolType() == 1) {
        packData.protocol = "ICMP";

        auto *icmpHeader = (ICMPHeader *) (packet + LINK_OFFSET + ipHeaderLength);

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

        const uint32_t payloadLength = header->caplen - (LINK_OFFSET + ipHeaderLength + icmpLen);
        const u_char *payload = packet + LINK_OFFSET + ipHeaderLength + icmpLen;
        if (payloadLength > 0){
            packData.hex = getPayload(payload, payloadLength);
        }
        else packData.hex = "no payload";
        emit packetCaptured(packData);
    }
}


void LoopBackHandler::saveJsonStatistic(const struct pcap_pkthdr *header,
                                const u_char *packet, bool flag, const std::string& type) const{
    json j;
    auto now = std::chrono::system_clock::now();
    auto time_point = std::chrono::system_clock::to_time_t(now);
    std::string time_str = std::ctime(&time_point);
    time_str.pop_back();
    j["timestamp"] = time_str;

    Ipv4Header* ipv4Header = (Ipv4Header *) (packet + LINK_OFFSET);
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

