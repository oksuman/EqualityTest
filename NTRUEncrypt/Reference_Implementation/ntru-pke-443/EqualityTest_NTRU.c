
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <inttypes.h>
#include <ctype.h>
#include <math.h>
#include <assert.h>
#include "NTRUEncrypt.h"

#define MESSAGE_HEX_SIZE 8 // 32bit

int enc(uint16_t *c, const char *m, unsigned long long mlen, uint16_t *h, const PARAM_SET *param);
int dec(char *m, uint16_t *c, uint16_t *F, uint16_t *h, const PARAM_SET *param);
void add(uint16_t *c, uint16_t *c1, uint16_t *c2, const PARAM_SET *param);

int main(int argc, char* argv[]) {
    srand(time(NULL));

    PARAM_SET_ID pid = NTRU_CCA_443;
    const PARAM_SET* param = get_param_set_by_id(pid);
    const size_t msg_len = 8; /* message length in bytes, 443 param 에서는 33byte가 최대 길이 */
    /*
    N : 443
    NAEP 적용 message size 270bit
    Message <= 33bytes
    */

    char* aliceHexPlainText = (char*)malloc(sizeof(char) * MESSAGE_HEX_SIZE + 1);
    char* bobHexPlainText = (char*)malloc(sizeof(char) * MESSAGE_HEX_SIZE + 1);

    uint16_t* c1 = (uint16_t*)malloc(sizeof(uint16_t) * param->N);
    uint16_t* c2 = (uint16_t*)malloc(sizeof(uint16_t) * param->N);
    uint16_t* c3 = (uint16_t*)malloc(sizeof(uint16_t) * param->N);

    char* aliceDecText = (char*)malloc(sizeof(char) * MESSAGE_HEX_SIZE + 1);
    char* bobDecText = (char*)malloc(sizeof(char) * MESSAGE_HEX_SIZE + 1);
    char* addDecText = (char*)malloc(sizeof(char) * MESSAGE_HEX_SIZE + 1);

    
    /* key generation */
    uint16_t* F = (uint16_t*)malloc(sizeof(uint16_t) * param->padN);        //SK
    uint16_t* g = (uint16_t*)malloc(sizeof(uint16_t) * param->padN);        //SK
    uint16_t* h = (uint16_t*)malloc(sizeof(uint16_t) * param->padN);        //PK
    uint16_t *buf = malloc (sizeof(uint16_t)*param->padN * 6);

    keygen(F, g, h, buf, param);
    free(buf);

    /* encoding */
    int16_t aliceNumber = 150;
    int16_t bobNumber = 1675;

   
    snprintf(aliceHexPlainText, MESSAGE_HEX_SIZE + 1, "%08x", aliceNumber);
    snprintf(bobHexPlainText, MESSAGE_HEX_SIZE + 1, "%08x", bobNumber);


    printf("aliceHexPlainText : %s\n", aliceHexPlainText);
    printf("bobHexPlainText : %s\n", bobHexPlainText);

    /* encryption */
    enc(c1, aliceHexPlainText, msg_len, h, param);
    enc(c2, bobHexPlainText, msg_len, h, param);

    /* decryption */
    dec(aliceDecText, c1, F, h, param);
    dec(bobDecText, c2, F, h, param);

    printf("aliceDecText : %s\n", aliceDecText);
    printf("bobDecText : %s\n", bobDecText);


    /* add */
    add(c3, c1, c2, param);
    printf("%d\n", dec(addDecText, c3, F, h, param));
    printf("addDecText : %s\n", addDecText);
    printf("%s\n", addDecText);


    free(F);
    free(g);
    free(h);
    free(aliceHexPlainText);
    free(bobHexPlainText);
    free(c1);
    free(c2);
    free(c3);
    free(aliceDecText);
    free(bobDecText);
    return 0;
}

int enc(uint16_t *c, const char *m, unsigned long long mlen, uint16_t *h, const PARAM_SET *param)
{
    if (param->id!=NTRU_CCA_443 && param->id != NTRU_CCA_743)
    {
        printf("unsupported parameter sets\n");
        return -1;
    }   

    uint16_t *buf;

    buf = malloc(sizeof(uint16_t)*param->padN*6);
        
    if(!buf)
    {
        printf("malloc error\n");
        return -1;
    }
    memset(buf,0, sizeof(uint16_t)*param->padN*6);

    encrypt_cca(c, m, mlen, h, buf, param);


    memset(buf,0, sizeof(uint16_t)*param->padN*6);

    free(buf);

    return 0;
}

int dec(char *m, uint16_t *c, uint16_t *F, uint16_t *h, const PARAM_SET *param){

    if (param->id!=NTRU_CCA_443 && param->id != NTRU_CCA_743)
    {
        printf("unsupported parameter sets\n");
        return -1;
    }

    uint16_t *buf;
    buf = malloc(sizeof(uint16_t)*param->padN*8);

    if(!buf)
    {
        printf("malloc error\n");
        return -1;
    }
    memset(buf,0, sizeof(uint16_t)*param->padN*8);

    decrypt_cca(m, F, h, c, buf, param);

    free(buf);

    return 0;
}

void add(uint16_t *c, uint16_t *c1, uint16_t *c2, const PARAM_SET *param){
    printf("c1 : \n");
    for (int i=0;i<param->N;i++)
        printf("%d, ", c1[i]);

    printf("\n\nc2 : \n");
    for (int i=0;i<param->N;i++)
        printf("%d, ", c2[i]);

    printf("\n\nc : \n");
    for (int i=0;i<param->N;i++){
        c[i] = (c1[i] - c2[i]) & (param->q-1);
        printf("%d, ", c[i]);
    }
    printf("\n");
}