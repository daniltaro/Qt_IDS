#include "threatdetector.h"
#include <QDebug>

bool threatDetector::isSuspiciousICMP(std::string& type){
    auto now = std::chrono::steady_clock::now();
    auto time = std::chrono::duration_cast<std::chrono::seconds>(now - start_timeICMP);
    bool flag = false;
    if(time.count() >= 5){
        if(icmp_count > 5){
            start_timeICMP = now;
            threatCount++;
            flag = true;

            type += "[ICMP FLOOD] ";
            qDebug() << "[ICMP FLOOD] " << "detected";
        } else {
            start_timeICMP = now;
            icmp_count = 0;
        }
    }
    return flag;
}

bool threatDetector::isSuspiciousTCP(std::string& type){
    auto now = std::chrono::steady_clock::now();
    auto time = std::chrono::duration_cast<std::chrono::seconds>(now - start_timeTCP);
    bool flag = false;

    if(time.count() >= 5){
        if (tcpSYN > 20 && ((double)tcpACK / tcpSYN) < 0.2){
            start_timeTCP = now;
            tcpACK = 0;
            tcpSYN = 0;
            flag = true;
            threatCount++;

            type += "[SYN FLOOD] ";
            qDebug() << "[SYN FLOOD] " << "detected";
        } else {
            start_timeTCP = now;
            tcpACK = 0;
            tcpSYN = 0;
        }

        for(const auto& [ip, ports] : TCPscanner){
            if(ports.size() > 5){
                flag = true;
                threatCount++;

                type += "[TCP PORT SCANING] ";
                qDebug() << "[TCP PORT SCANING] " << "detected";
            }
        }
    }
    return flag;
}

bool threatDetector::issuspiciousUDP(std::string& type){
    auto now = std::chrono::steady_clock::now();
    auto time = std::chrono::duration_cast<std::chrono::seconds>(now - start_timeUDP);
    bool flag = false;

    if(time.count() >= 5){
        if(UDP_packets > 100){
            start_timeUDP = now;
            UDP_packets = 0;
            flag = true;
            threatCount++;

            type += "[UDP FLOOD] ";
            qDebug() << "[UDP FLOOD] " << "detected";
        } else {
            UDP_packets = 0;
            start_timeUDP = now;
        }

        for(const auto& [ip, ports] : UDPscanner){
            if(ports.size() > 5){
                flag = true;
                threatCount++;

                type += "[UDP PORT SCANING] ";
                qDebug() << "[UDP PORT SCANING] " << "detected";
            }
        }


    }
    return flag;
}

void threatDetector::tcpSYNAdd(){
    tcpSYN += 1;
}

void threatDetector::tcpACKAdd(){
    tcpACK += 1;
}

void threatDetector::icmpTypeAdd(){
    icmp_count += 1;
}

void threatDetector::udpAdd(){
    UDP_packets += 1;
}

int threatDetector::getThreatCount() const{
    return threatCount;
}

void threatDetector::addIPv4srcDstTCP(const std::string& ip, const u_int16_t& dst_port){
    TCPscanner[ip].insert(dst_port);
}

void threatDetector::addIPv4srcDstUDP(const std::string& ip, const u_int16_t& dst_port){
    UDPscanner[ip].insert(dst_port);
}
