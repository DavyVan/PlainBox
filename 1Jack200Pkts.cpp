//Sniff 200 packets and print its length for every packet

#include<cstdio>
#include<pcap.h>
using namespace std;

void got_pkt(u_char *args, const pcap_pkthdr *header, const u_char *packet)
{
    printf("Got a packet which has length of [%d]\n", header->len);
    return;
}

int main(int argc, char *argv[])
{
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    pcap_pkthdr header;
    const u_char *packet;

    dev = pcap_lookupdev(errbuf);
    if(dev == NULL)
    {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 2;
    }
    printf("Device: %s\n", dev);

    handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
    if(handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }
    if(pcap_datalink(handle) != DLT_EN10MB)
    {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
        return 2;
    }

    pcap_loop(handle, 200, got_pkt, NULL);

    pcap_close(handle);

    return 0;
}
