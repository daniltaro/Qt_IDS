#include "basehandler.h"

void BaseHandler::StaticHandle(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    BaseHandler *data = reinterpret_cast<BaseHandler *>(args);
    data->Handle(header, packet);
}
