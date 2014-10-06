/*
| ------------------------------------------------------------------------------
| File:     encrypt.h
| Purpose:  Encryption algorithms
| 
| ------------------------------------------------------------------------------
*/

#include <string.h>

/*
| ------------------------------------------------------------------------------
| XOR Encryption
| 
| (No need for decryption because XOR'ing twice, gives back the original string)
| ------------------------------------------------------------------------------
*/

int xor_encrypt(char *plaintext, char *key, int n){
    
    /* XOR each byte with key, repeating key if too short */
    
    int c;
    int keylen = strlen(key);
    for(c = 0;c < n;c++){
        plaintext[c] = plaintext[c] ^ key[c % keylen];
    }
    
    return 1;
}
