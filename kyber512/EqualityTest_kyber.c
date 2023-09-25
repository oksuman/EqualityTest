#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "indcpa.h"
#include "params.h"

const unsigned char* generateCoin() {
    static unsigned char seed[KYBER_SYMBYTES]; 

    for (size_t i = 0; i < KYBER_SYMBYTES; ++i) {
        seed[i] = rand() % 256; 
    }
    return seed;
}


int main(int argc, char* argv[]){
    printf("its okay 0\n");
    const unsigned char* coin = generateCoin();

    unsigned char msg1[KYBER_INDCPA_MSGBYTES] = {0}; 
    unsigned char msg2[KYBER_INDCPA_MSGBYTES] = {0};
    unsigned char msg3[KYBER_INDCPA_MSGBYTES] = {0};
    unsigned char msg4[KYBER_INDCPA_MSGBYTES] = {0};


    msg1[KYBER_INDCPA_MSGBYTES-1] = 20;
    msg2[KYBER_INDCPA_MSGBYTES-1] = 20;

    
    unsigned char ctx1[KYBER_INDCPA_BYTES];
    unsigned char ctx2[KYBER_INDCPA_BYTES];
    unsigned char ctx3[KYBER_INDCPA_BYTES];
    unsigned char ctx4[KYBER_INDCPA_BYTES];

    unsigned char pk[KYBER_INDCPA_PUBLICKEYBYTES];
    unsigned char sk[KYBER_INDCPA_SECRETKEYBYTES];

    indcpa_keypair(pk, sk);

    indcpa_enc(ctx1, msg1, pk, coin);
    indcpa_enc(ctx2, msg2, pk, coin);

    add(ctx3, ctx1, ctx2);
    randomize_poly(ctx4, ctx3, 1);
    
    indcpa_dec(msg3, ctx3, sk);
    
    
    printf("msg1 contents: ");
    for (int i = 0; i < KYBER_INDCPA_MSGBYTES; i++) {
        printf("%02X ", msg1[i]);
    }
    printf("\n");
    
    printf("msg2 contents: ");
    for (int i = 0; i < KYBER_INDCPA_MSGBYTES; i++) {
        printf("%02X ", msg2[i]);
    }
    printf("\n");
    
    printf("msg3 contents: ");
    for (int i = 0; i < KYBER_INDCPA_MSGBYTES; i++) {
        printf("%02X ", msg3[i]);
    }
    printf("\n");
    

    printf("msg4 contents: ");
    for (int i = 0; i < KYBER_INDCPA_MSGBYTES; i++) {
        printf("%02X ", msg4[i]);
    }
    printf("\n");
  
    return 0;
}

// gcc -o EqualityTest_kyber EqualityTest_kyber.c indcpa.c -lssl -lcrypto -lrt



q