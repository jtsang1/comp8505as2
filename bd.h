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
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

/*
| ------------------------------------------------------------------------------
| Constants
| ------------------------------------------------------------------------------
*/

#define PKT_SIZE        4096
#define WIN_SIZE        55840
#define DEFAULT_TTL		255
#define DEFAULT_IP_ID   12345
/*
| ------------------------------------------------------------------------------
| Prototypes
| ------------------------------------------------------------------------------
*/

/* Options to pass to client function */

struct client_opt{
    char target_host[128];
    char command[128];
    int target_port;
};

/* TCP checksum pseudo-header */

typedef struct {
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
    struct tcphdr tcp;
}pseudo_header;

/* Raw socket object with options */

struct addr_info {

    int raw_socket;
    char *dhost;
    char *shost;
    int dport;
    int sport;
};

void client(struct client_opt);
void server();
void packet_handler();
void usage();
unsigned short csum(unsigned short *, int);

