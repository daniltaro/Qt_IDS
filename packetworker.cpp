#include "packetworker.h"
#include "ethernethandler.h"
// #include "loopbackhandler.h"

extern char ebuf[PCAP_ERRBUF_SIZE];
extern std::string save_buf;

PacketWorker::PacketWorker(const std::string& dev, bool tcp, bool icmp, bool udp, bool all)
    :   dev(dev), tcp(tcp), icmp(icmp), udp(udp), all(all){}

PacketWorker::~PacketWorker(){
    if(handle) pcap_close(handle);
}

void PacketWorker::startCapture(){
    handle = pcap_open_live(dev.c_str(), BUFSIZ, 1, 1, ebuf);
    if(!handle){
        emit finished();
        throw std::runtime_error(ebuf);
    }

    int link_type = pcap_datalink(handle);
    BaseHandler* handler = nullptr;

    if (link_type == DLT_EN10MB) handler = new EthernetHandler(all, tcp, udp, icmp);
    // else if (link_type == DLT_NULL || link_type == DLT_LOOP) handler = new LoopBackHandler(all, tcp, udp, icmp);
    else{
        qDebug("linkTypeError");
        emit linkTypeError();
        return;
    }

    connect(handler, &BaseHandler::packetCaptured, this, &PacketWorker::packetCaptured);
    connect(handler, &BaseHandler::statReady, this, &PacketWorker::statReady);

    save_buf += "[\n";

    pcap_loop(handle, -1, BaseHandler::StaticHandle, reinterpret_cast<u_char*>(handler));

    handler->printStatistic();
    save_buf += "\n]";

    emit finished();
}

void PacketWorker::stopCapture(){
    if(handle){
        pcap_breakloop(handle);
    }
}
