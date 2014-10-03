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
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "bd.h"

/*
| ------------------------------------------------------------------------------
| Main Function
| ------------------------------------------------------------------------------
*/

int main(int argc, char **argv){

    /* Parse arguments */
    
    int opt;
    int is_server = 0;
    char target_host[128], command[128];
    target_host[0] = '\0';
    command[0] = '\0';
    while((opt = getopt(argc, argv, "hsd:x:")) != -1){
        switch(opt){
            case 'h':
                usage();
                return 0;
                break;
            case 's':
                is_server = 1;
                break;
            case 'd':
                strcpy(target_host, optarg);
                break;
            case 'x':
                strcpy(command, optarg);
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
        if(target_host[0] == '\0' || command[0] == '\0'){
            printf("Type -h for usage help.\n");
            return 1;
        }
        else{
            client();
        }
    }
    
    return 0;
}

/*
| ------------------------------------------------------------------------------
| Client
| ------------------------------------------------------------------------------
*/

void client(){

    printf("Running client...\n");
    
    /* Encrypt command */
    
    /* Craft packet with options */
    
    /* Send packet */
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
| Packet Handler Function
| ------------------------------------------------------------------------------
*/

void packet_handler(){
    
    /* Check the packet for the header key meant for the backdoor */
    
    /* Decrypt remaining packet data */
    
    /* Verify decryption succeeds by checking for custom header and footer */
    
    /* All checks successful, run the system command */
    
}

/*
| ------------------------------------------------------------------------------
| Usage printout
| ------------------------------------------------------------------------------
*/

void usage(){
    
    printf("\n");
    printf("Usage: ./backdoor [OPTIONS]\n");
    printf("-------------------------------------------------------------------------\n");
    printf("  -h                Display this help.\n");
    printf("CLIENT (default)\n");
    printf("  -d <target_host>  The target host where the backdoor server is running.\n");
    printf("  -x <command>      The command to run on the target host.\n");
    printf("SERVER\n");
    printf("  -s                Enables server mode. No other options necessary.\n");
    printf("\n");
}
