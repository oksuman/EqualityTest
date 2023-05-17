// g++ -o ECE ECE.cpp -lssl -lcrypto

#include <iostream>
#include <cstring>
#include "ECE.h"

#define STR_LENGTH 512

using namespace std;

ECE::ECE()
{
    bn_ctx = BN_CTX_new();
    q = BN_new();
    x = BN_new();

    if (NULL == (E = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)))
        handleErrors();

    if ((G = EC_GROUP_get0_generator(E)) == NULL)
        handleErrors();

    if (EC_GROUP_get_order(E, q, bn_ctx) == 0) // return 1 on success and 0 if an error occurred
        handleErrors();

    X = EC_POINT_new(E);
}

ECE::~ECE()
{
    BN_free(q);
    BN_free(x);
    BN_CTX_free(bn_ctx);
    EC_POINT_free((EC_POINT *)G);
    EC_POINT_free(X);
    EC_GROUP_free(E);
}

void ECE::KeyGen()
{
    if (!BN_rand_range(x, q)) // x
        handleErrors();

    EC_POINT_mul(E, X, x, NULL, NULL, bn_ctx); // X = xG
}

CIPHERTEXT *ECE::Enc(const unsigned char *M)
{
    BIGNUM *m = BN_new();
    BIGNUM *r = BN_new();

    EC_POINT *C1 = EC_POINT_new(E);
    EC_POINT *C2 = EC_POINT_new(E);

    CIPHERTEXT *C = new CIPHERTEXT;

    C->C1 = new unsigned char[STR_LENGTH];
    C->C2 = new unsigned char[STR_LENGTH];

    memset(C->C1, 0x00, STR_LENGTH);
    memset(C->C2, 0x00, STR_LENGTH);

    BN_hex2bn(&m, (char *)M);

    if (!BN_rand_range(r, q))
        handleErrors();

    EC_POINT_mul(E, C1, r, NULL, NULL, bn_ctx); // C1 = rG
    EC_POINT_mul(E, C2, m, X, r, bn_ctx);       // C2 = mG + rX

    strcpy((char *)C->C1, EC_POINT_point2hex(E, C1, EC_GROUP_get_point_conversion_form(E), bn_ctx));
    strcpy((char *)C->C2, EC_POINT_point2hex(E, C2, EC_GROUP_get_point_conversion_form(E), bn_ctx));

    BN_free(m);
    BN_free(r);
    EC_POINT_free(C1);
    EC_POINT_free(C2);

    return C;
}

unsigned char *ECE::Dec(const CIPHERTEXT _C)
{
    EC_POINT *C1 = EC_POINT_new(E);
    EC_POINT *C2 = EC_POINT_new(E);
    EC_POINT *C = EC_POINT_new(E);
    unsigned char *ret = new unsigned char[STR_LENGTH];

    memset(ret, 0x00, STR_LENGTH);

    EC_POINT_hex2point(E, (const char *)_C.C1, C1, bn_ctx);
    EC_POINT_hex2point(E, (const char *)_C.C2, C2, bn_ctx);

    EC_POINT_mul(E, C1, NULL, C1, x, bn_ctx); // C1 = x C1 = xrG

    EC_POINT_invert(E, C1, bn_ctx); // C1 = -C1

    EC_POINT_add(E, C, C1, C2, bn_ctx); // C = C1 + C2 = C2 - C1 = mG

    strcpy((char *)ret, EC_POINT_point2hex(E, C, EC_GROUP_get_point_conversion_form(E), bn_ctx));

    return ret; // ret = mG
}

CIPHERTEXT *ECE::Scalar_Mul(const unsigned char *_s, const CIPHERTEXT _C)
{
    BIGNUM *s = BN_new();
    EC_POINT *C1 = EC_POINT_new(E);
    EC_POINT *C2 = EC_POINT_new(E);

    CIPHERTEXT *C = new CIPHERTEXT;
    C->C1 = new unsigned char[STR_LENGTH];
    C->C2 = new unsigned char[STR_LENGTH];

    memset(C->C1, 0x00, STR_LENGTH);
    memset(C->C2, 0x00, STR_LENGTH);

    BN_hex2bn(&s, (char *)_s);

    EC_POINT_hex2point(E, (const char *)_C.C1, C1, bn_ctx);
    EC_POINT_hex2point(E, (const char *)_C.C2, C2, bn_ctx);

    EC_POINT_mul(E, C1, NULL, C1, s, bn_ctx); // C1 = sC1
    EC_POINT_mul(E, C2, NULL, C2, s, bn_ctx); // C2 = sC2

    strcpy((char *)C->C1, EC_POINT_point2hex(E, C1, EC_GROUP_get_point_conversion_form(E), bn_ctx));
    strcpy((char *)C->C2, EC_POINT_point2hex(E, C2, EC_GROUP_get_point_conversion_form(E), bn_ctx));

    BN_free(s);
    EC_POINT_free(C1);
    EC_POINT_free(C2);

    return C;
}

CIPHERTEXT *ECE::Add(const CIPHERTEXT Ci, const CIPHERTEXT Cj) // Ci + Cj
{
    EC_POINT *Ci1 = EC_POINT_new(E);
    EC_POINT *Ci2 = EC_POINT_new(E);
    EC_POINT *Cj1 = EC_POINT_new(E);
    EC_POINT *Cj2 = EC_POINT_new(E);

    CIPHERTEXT *C = new CIPHERTEXT;
    C->C1 = new unsigned char[STR_LENGTH];
    C->C2 = new unsigned char[STR_LENGTH];

    memset(C->C1, 0x00, STR_LENGTH);
    memset(C->C2, 0x00, STR_LENGTH);

    EC_POINT_hex2point(E, (const char *)Ci.C1, Ci1, bn_ctx);
    EC_POINT_hex2point(E, (const char *)Ci.C2, Ci2, bn_ctx);
    EC_POINT_hex2point(E, (const char *)Cj.C1, Cj1, bn_ctx);
    EC_POINT_hex2point(E, (const char *)Cj.C2, Cj2, bn_ctx);

    EC_POINT_add(E, Ci1, Ci1, Cj1, bn_ctx); // Ci1 = Ci1 + Ci2
    EC_POINT_add(E, Ci2, Ci2, Cj2, bn_ctx); // Ci2 = Ci2 + Cj2

    strcpy((char *)C->C1, EC_POINT_point2hex(E, Ci1, EC_GROUP_get_point_conversion_form(E), bn_ctx));
    strcpy((char *)C->C2, EC_POINT_point2hex(E, Ci2, EC_GROUP_get_point_conversion_form(E), bn_ctx));
    
    EC_POINT_free(Ci1);
    EC_POINT_free(Ci2);
    EC_POINT_free(Cj1);
    EC_POINT_free(Cj2);

    return C;
}
CIPHERTEXT *ECE::Sub(const CIPHERTEXT Ci, const CIPHERTEXT Cj) // Ci - Cj
{
    EC_POINT *Ci1 = EC_POINT_new(E);
    EC_POINT *Ci2 = EC_POINT_new(E);
    EC_POINT *Cj1 = EC_POINT_new(E);
    EC_POINT *Cj2 = EC_POINT_new(E);

    CIPHERTEXT *C = new CIPHERTEXT;
    C->C1 = new unsigned char[STR_LENGTH];
    C->C2 = new unsigned char[STR_LENGTH];

    memset(C->C1, 0x00, STR_LENGTH);
    memset(C->C2, 0x00, STR_LENGTH);

    EC_POINT_hex2point(E, (const char *)Ci.C1, Ci1, bn_ctx);
    EC_POINT_hex2point(E, (const char *)Ci.C2, Ci2, bn_ctx);
    EC_POINT_hex2point(E, (const char *)Cj.C1, Cj1, bn_ctx);
    EC_POINT_hex2point(E, (const char *)Cj.C2, Cj2, bn_ctx);

    EC_POINT_invert(E, Cj1, bn_ctx); // Cj1 = -Cj1
    EC_POINT_invert(E, Cj2, bn_ctx); // Cj2 = -Cj2

    EC_POINT_add(E, Ci1, Ci1, Cj1, bn_ctx); // Ci1 = Ci1 + (-Cj1)
    EC_POINT_add(E, Ci2, Ci2, Cj2, bn_ctx); // Ci2 = Ci2 + (-Cj2)

    strcpy((char *)C->C1, EC_POINT_point2hex(E, Ci1, EC_GROUP_get_point_conversion_form(E), bn_ctx));
    strcpy((char *)C->C2, EC_POINT_point2hex(E, Ci2, EC_GROUP_get_point_conversion_form(E), bn_ctx));
    
    EC_POINT_free(Ci1);
    EC_POINT_free(Ci2);
    EC_POINT_free(Cj1);
    EC_POINT_free(Cj2);

    return C;
}

unsigned char * ECE::getRandomElement()
{
    BIGNUM *r = BN_new();
    unsigned char *ret = new unsigned char[STR_LENGTH];

    memset(ret, 0x00, STR_LENGTH);

    if (!BN_rand_range(r, q))
        handleErrors();

    strcpy((char*)ret, BN_bn2hex(r));

    BN_free(r);

    return ret;
}
