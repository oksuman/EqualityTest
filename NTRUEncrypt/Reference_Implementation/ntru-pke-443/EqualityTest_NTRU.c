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

void print_hex(const uint16_t *arr, size_t size) {
    for (size_t i = 0; i < size; i++) {
        printf("%04x ", arr[i]);
    }
    printf("\n");
}

void generate_random_numbers(uint16_t *arr, size_t size, uint16_t min_value, uint16_t max_value) {
    for (size_t i = 0; i < size; i++) {
        arr[i] = min_value + rand() % (max_value - min_value + 1);
    }
}

int main(int argc, char* argv[]) {
    srand(time(NULL));

    PARAM_SET_ID pid = NTRU_KEM_443;
    const PARAM_SET* param = get_param_set_by_id(pid);
    const size_t msg_len = 4; /* message length in bytes, 443 param 에서는 33byte가 최대 길이 */
    /*
    N : 443
    NAEP 적용 message size 270bit
    Message <= 33bytes
    */

    /* key generation */
    printf("about to key gen\n");
    char* aliceHexPlainText = (char*)malloc(sizeof(char) * MESSAGE_HEX_SIZE + 1);
    char* bobHexPlainText = (char*)malloc(sizeof(char) * MESSAGE_HEX_SIZE + 1);
    char* aliceDecText = (char*)malloc(sizeof(char) * MESSAGE_HEX_SIZE + 1);
    char* bobDecText = (char*)malloc(sizeof(char) * MESSAGE_HEX_SIZE + 1);
    uint16_t* c1 = (uint16_t*)malloc(sizeof(uint16_t) * param->N);
    uint16_t* c2 = (uint16_t*)malloc(sizeof(uint16_t) * param->N);
    uint16_t* F = (uint16_t*)malloc(sizeof(uint16_t) * param->padN);
    uint16_t* g = (uint16_t*)malloc(sizeof(uint16_t) * param->padN);
    uint16_t* h = (uint16_t*)malloc(sizeof(uint16_t) * param->padN);
    uint16_t* buf = (uint16_t*)malloc(sizeof(uint16_t) * param->padN);

    keygen(F, g, h, buf, param);

    printf("F: \n");
    for (int i=0;i<param->padN;i++)
        printf("%d, ", F[i]);
    printf("\n");

    // for (int i = 0; i < param->N; i++) {
    //     assert(h[i] >= 0 && h[i] < param->q);
    // }
    // printf("h: \n");
    // for (int i=0;i<param->padN;i++)
    //     printf("%d, ", h[i]);
    // printf("\n");

    printf("after key gen\n");
    int16_t aliceNumber = 150;
    int16_t bobNumber = 1675;

    /* endcoding */

    snprintf(aliceHexPlainText, MESSAGE_HEX_SIZE + 1, "%08x", aliceNumber);
    snprintf(bobHexPlainText, MESSAGE_HEX_SIZE + 1, "%08x", bobNumber);

    printf("aliceHexPlainText : %s\n", aliceHexPlainText);
    printf("bobHexPlainText : %s\n", bobHexPlainText);

    encrypt_cca(c1, aliceHexPlainText, msg_len, h, buf, param);
    encrypt_cca(c2, bobHexPlainText, msg_len, h, buf, param);

    printf("ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ복호화시작ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ\n");
    printf("ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ한턴쉬고ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ\n");
    decrypt_cca(aliceDecText, F, h, c1, buf, param);
    decrypt_cca(bobDecText, F, h, c2, buf, param);
    

    printf("aliceDecText : %s\n", aliceHexPlainText);
    printf("bobDecText : %s\n", bobHexPlainText);

    free(F);
    free(g);
    free(h);
    // free(c1);
    // free(c2);
    // free(aliceHexPlainText);
    // free(bobHexPlainText);
    // free(buf);
    return 0;
}
