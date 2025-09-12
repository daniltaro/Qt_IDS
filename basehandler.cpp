#include "basehandler.h"

void BaseHandler::StaticHandle(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    UserData *data = reinterpret_cast<UserData *>(args);
    data->handler->Handle(reinterpret_cast<u_char *>(data), header, packet);
}
