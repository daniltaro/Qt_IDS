#include "packetworker.h"
#include "ethernethandler.h"
// #include "loopbackhandler.h"

extern char ebuf[PCAP_ERRBUF_SIZE];
std::string save_buf;

PacketWorker::PacketWorker(const std::string& dev, bool tcp, bool icmp, bool udp, bool all,
                           const std::string& json_file_name)
    :   dev(dev), tcp(tcp), icmp(icmp), udp(udp), all(all), jsonPath(json_file_name){}

PacketWorker::~PacketWorker(){
    if(handle) pcap_close(handle);
}

void PacketWorker::startCapture(){
    handle = pcap_open_live(dev.c_str(), BUFSIZ, 1, 10, ebuf);
    if(!handle){
        emit finished();
        return;
    }

    int link_type = pcap_datalink(handle);
    BaseHandler* handler = nullptr;

    if (link_type == DLT_EN10MB) handler = new EthernetHandler(all, tcp, udp, icmp);
    // else if (link_type == DLT_NULL || link_type == DLT_LOOP) handler = new LoopBackHandler(all, tcp, udp, icmp);

    connect(handler, &BaseHandler::packetCaptured, this, &PacketWorker::packetCaptured);
    connect(handler, &BaseHandler::statReady, this, &PacketWorker::statReady);

    save_buf += "[\n";

    data = {handler ,save_buf};

    pcap_loop(handle, -1, BaseHandler::StaticHandle, reinterpret_cast<u_char*>(&data));

    handler->printStatistic();
    save_buf += "\n]";

    delete handler;

    emit finished();
}

void PacketWorker::stopCapture(){
    if(handle) pcap_breakloop(handle);
}
