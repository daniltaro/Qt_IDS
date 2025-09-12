#ifndef BASEHANDLER_H
#define BASEHANDLER_H

#include <pcap.h>
#include <string>
#include <fstream>
#include <iostream>
#include <QString>
#include <QObject>

enum protocolType {
    ALL = 0,
    TCP = 6,
    UDP = 17,
    ICMP = 1,
};

struct PacketData{
    QString protocol;
    QString type;
    QString srcDst;
};

class BaseHandler : public QObject{
    Q_OBJECT
protected:
    int pack_count = 0;
    PacketData packData;
public:
    virtual void Handle(u_char *user, const struct pcap_pkthdr
            *header, const u_char *packet) = 0;
    virtual void printStatistic() = 0;
    virtual void saveGenStatistic() = 0;
    virtual ~BaseHandler() {}
    static void StaticHandle(u_char *user,
        const struct pcap_pkthdr *header, const u_char *packet);
signals:
    void packetCaptured(PacketData);

    void statReady(QString);
};

struct UserData{
    BaseHandler* handler;
    std::string save_buf;
};

#endif//BASEHANDLER_H
