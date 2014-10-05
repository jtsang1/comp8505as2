/*
| ------------------------------------------------------------------------------
| File:     packet_headers.h
| Purpose:  Define packet header structures and functions
|
| ------------------------------------------------------------------------------
*/

#define ETHER_ADDR_LEN  6   /* Ethernet addresses are 6 bytes */
#define SIZE_ETHERNET   14  /* Ethernet headers are always exactly 14 bytes */

/* Ethernet header */

struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */

struct sniff_ip {
    u_char ip_vhl;          /* version << 4 | header length >> 2 */
    u_char ip_tos;          /* type of service */
    u_short ip_len;         /* total length */
    u_short ip_id;          /* identification */
    u_short ip_off;         /* fragment offset field */
#define IP_RF 0x8000        /* reserved fragment flag */
#define IP_DF 0x4000        /* dont fragment flag */
#define IP_MF 0x2000        /* more fragments flag */
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
    u_char ip_ttl;          /* time to live */
    u_char ip_p;            /* protocol */
    u_short ip_sum;         /* checksum */
    struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)        (((ip)->ip_vhl) >> 4)

/* TCP header */

typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;       /* source port */
    u_short th_dport;       /* destination port */
    tcp_seq th_seq;         /* sequence number */
    tcp_seq th_ack;         /* acknowledgement number */
    u_char th_offx2;        /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;         /* window */
    u_short th_sum;         /* checksum */
    u_short th_urp;         /* urgent pointer */
};

/* Structure to hold all the parsed headers */

struct tcp_ip_packet{
    const struct sniff_ethernet *ethernet;
    const struct sniff_ip *ip;
    const struct sniff_tcp *tcp;
    const u_char *payload;
};

/* Typecast the packet into multiple header structures */

int tcp_ip_typecast(const u_char *packet, struct tcp_ip_packet *packet_info){

    u_int size_ip;
    u_int size_tcp;
    
    // Ethernet
    packet_info->ethernet = (struct sniff_ethernet *)(packet);
    
    // IP
    packet_info->ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(packet_info->ip)*4;
    if(size_ip < 20){
        printf("Invalid IP header length: %u bytes\n", size_ip);
        return 0;
    }
    
    // TCP
    packet_info->tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(packet_info->tcp)*4;
    if(size_tcp < 20){
        printf("Invalid TCP header length: %u bytes\n",size_tcp);
        return 0;
    }
    packet_info->payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    
    return 1;
}
