#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <inttypes.h>
#include <ctype.h>
#include <math.h>
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
    uint16_t *F = NULL; /* output secret key f */
    uint16_t *g = NULL; /* optional output secret key g */
    uint16_t *h = NULL; /* output public key h */
    uint16_t *buf = NULL;
    keygen(&F, &g, &h, &buf, param);


    int16_t aliceNumber = 150;
    int16_t bobNumber = 1675;

    /* endcoding */
    char aliceHexPlainText[MESSAGE_HEX_SIZE];
    char bobHexPlainText[MESSAGE_HEX_SIZE];

    snprintf(aliceHexPlainText, sizeof(aliceHexPlainText), "%04x", aliceNumber);
    snprintf(bobHexPlainText, sizeof(bobHexPlainText), "%04x", bobNumber);

    printf("come3\n");
    printf("aliceHexPlainText : %s\n", aliceHexPlainText);
    printf("bobHexPlainText : %s\n", bobHexPlainText);

    uint16_t *c1 = NULL;
    uint16_t *c2 = NULL;

    printf("come2\n");
    encrypt_cca(&c1, aliceHexPlainText, msg_len, h, buf, param);
    encrypt_cca(&c2, bobHexPlainText, msg_len, h, buf, param);

    printf("aliceCipherText : ");
    // print_hex(c1, param->ct_len);
    printf("bobHexCipherText : ");
    // print_hex(c2, param->ct_len)

    char aliceDecryptMessage[MESSAGE_HEX_SIZE];
    char bobDecryptMessage[MESSAGE_HEX_SIZE];
    printf("come\n");
    decrypt_cca(&aliceDecryptMessage, F, h, c1, buf, param);
    decrypt_cca(&bobDecryptMessage, F, h, c2, buf, param);

    printf("aliceDecryptMessage : %s\n", aliceDecryptMessage);
    printf("bobDecryptMessage : %s\n", bobDecryptMessage);

    // 메모리 해제
    if (F != NULL)
        free(F);
    if (g != NULL)
        free(g);
    if (h != NULL)
        free(h);
    if (buf != NULL)
        free(buf);
    if (c1 != NULL)
        free(c1);
    if (c2 != NULL)
        free(c2);
    // if (aliceDecryptMessage != NULL)
    //     free(aliceDecryptMessage);
    // if (bobDecryptMessage != NULL)
    //     free(bobDecryptMessage);

    return 0;
}
