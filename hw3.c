#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <string.h>
#include <time.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define MAC_ADDRSTRLEN 2*6+5+1
#define STR_BUF 16
const char *mac_ntoa(u_int8_t *d);
const char *ip_ntoa(void *i);
void dump_ethernet(u_int32_t length, const u_char *content);
void dump_ip(u_int32_t length, const u_char *content);
void dump_tcp(u_int32_t length, const u_char *content);
void dump_udp(u_int32_t length, const u_char *content);
void pcap_callback(u_char *arg, const struct pcap_pkthdr *header, const u_char *content);

int c = 0;
int count[1000] = {0};
char src_check[500][20];
char dst_check[500][20];

void ip_number_count(char* ip_src, char* ip_dst);

int main(int argc, const char * argv[]) {

    char errbuf[PCAP_ERRBUF_SIZE];
    const char *filename = argv[2];


    pcap_t *handle = pcap_open_offline(filename, errbuf);
    if(!handle) {
        fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
        exit(1);
    }

    pcap_loop(handle, 0, pcap_callback, NULL);

    int i;
    for(i = 0; i < c; i++)
        printf("Source IP: %s Destination IP: %s count: %d\n",src_check[i], dst_check[i], count[i]);

    pcap_close(handle);
    return 0;
}

const char *mac_ntoa(u_int8_t *d) {
    static char mac[STR_BUF][MAC_ADDRSTRLEN];
    static int which = -1;

    which = (which + 1 == STR_BUF ? 0 : which + 1);

    memset(mac[which], 0, MAC_ADDRSTRLEN);
    snprintf(mac[which], sizeof(mac[which]), "%02x:%02x:%02x:%02x:%02x:%02x", d[0], d[1], d[2], d[3], d[4], d[5]);

    return mac[which];
}

const char *ip_ntoa(void *i) {
    static char ip[STR_BUF][INET_ADDRSTRLEN];
    static int which = -1;

    which = (which + 1 == STR_BUF ? 0 : which + 1);

    memset(ip[which], 0, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, i, ip[which], sizeof(ip[which]));

    return ip[which];
}

void pcap_callback(u_char *arg, const struct pcap_pkthdr *header, const u_char *content) {
    struct tm *ltime;
    char timestr[100];
    time_t local_tv_sec;

    local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof timestr, "%04Y%02m%02d %H:%M:%S", ltime);

    //print header
    printf("\tTime: %s.%.6d\n", timestr, (int)header->ts.tv_usec);

    dump_ethernet(header->caplen, content);

    printf("\n");
}

void dump_ethernet(u_int32_t length, const u_char *content) {
    char dst_mac[MAC_ADDRSTRLEN] = {0};
    char src_mac[MAC_ADDRSTRLEN] = {0};
    u_int16_t type;

    struct ether_header *ethernet = (struct ether_header *)content;

    //copy header
    snprintf(dst_mac, sizeof(dst_mac), "%s", mac_ntoa(ethernet->ether_dhost));
    snprintf(src_mac, sizeof(src_mac), "%s", mac_ntoa(ethernet->ether_shost));
    type = ntohs(ethernet->ether_type);


    printf("\tDestination MAC Address: %17s\n", dst_mac);
    printf("\tSource MAC Address: %17s\n", src_mac);

    printf("Next type is ");

    switch (type) {
        case ETHERTYPE_ARP:
            printf("ARP\n");
            break;

        case ETHERTYPE_IP:
            printf("IP\n");
            dump_ip(length, content);
            break;

        case ETHERTYPE_REVARP:
            printf("RARP\n");
            break;

        case ETHERTYPE_IPV6:
            printf("IPv6\n");
            break;

        default:
            printf("%#06x\n", type);
            break;
    }
}

void dump_ip(u_int32_t length, const u_char *content) {
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    u_char protocol = ip->ip_p;

    char src_ip[INET_ADDRSTRLEN] = {0};
    char dst_ip[INET_ADDRSTRLEN] = {0};

    //copy ip address
    snprintf(src_ip, sizeof(src_ip), "%s", ip_ntoa(&ip->ip_src));
    snprintf(dst_ip, sizeof(dst_ip), "%s", ip_ntoa(&ip->ip_dst));

    ip_number_count(src_ip, dst_ip);

    printf("Protocol: IP\n");
    printf("\tSource IP Address: %15s\n", src_ip);
    printf("\tDestination IP Address: %15s\n", dst_ip);

    switch (protocol) {
        case IPPROTO_UDP:
            printf("Next is UDP\n");
            dump_udp(length, content);
            break;

        case IPPROTO_TCP:
            printf("Next is TCP\n");
            dump_tcp(length, content);
            break;

        case IPPROTO_ICMP:
            printf("Next is ICMP\n");
            break;

        default:
            printf("Next is %d\n", protocol);
            break;
    }
}

void ip_number_count(char* ip_src, char* ip_dst)
{
    int i;
    for(i = 0; i < c; i++){
        if(strcmp(ip_src, src_check[i]) == 0 && strcmp(ip_dst, dst_check[i]) == 0){
            count[i]++;
            return;
        }
    }
    strcpy(src_check[c], ip_src);
    strcpy(dst_check[c], ip_dst);
    count[c]++;
    c++;
}

void dump_tcp(u_int32_t length, const u_char *content) {
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    struct tcphdr *tcp = (struct tcphdr *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2));

    //copy header
    u_int16_t source_port = ntohs(tcp->th_sport);
    u_int16_t destination_port = ntohs(tcp->th_dport);

    printf("Protocol: TCP\n");
    printf("\tSource Port: %5u\n", source_port);
    printf("\tDestination Port: %5u\n", destination_port);
}

void dump_udp(u_int32_t length, const u_char *content) {
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    struct udphdr *udp = (struct udphdr *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2));

    u_int16_t source_port = ntohs(udp->uh_sport);
    u_int16_t destination_port = ntohs(udp->uh_dport);

    printf("Protocol: UDP\n");
    printf("\tSource Port: %5u\n", source_port);
    printf("\tDestination Port: %5u|\n", destination_port);
}
