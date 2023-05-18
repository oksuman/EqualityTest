// g++ -o GM GM.cpp -lssl -lcrypto

#include "GM.h"
#include <iostream>
#include <cstring>

GM::GM()
{
    bn_ctx = BN_CTX_new();
}

GM::~GM()
{
    BN_CTX_free(bn_ctx);
}

BIGNUM *GM::generate_random_prime1(int len = 1024)
{
    BIGNUM *prime = BN_new();
    BN_generate_prime_ex(prime, len, 0, NULL, NULL, NULL);
    return prime;
}

unsigned char *GM::generate_random_prime2(int len = 1024)
{
    unsigned char *ret = new unsigned char[STR_LENGTH];
    memset(ret, 0x00, STR_LENGTH);

    strcpy((char *)ret, BN_bn2hex(generate_random_prime1(len)));

    return ret;
}

BIGNUM *GM::generate_random_element1(const BIGNUM *n)
{
    BIGNUM *random = BN_new();
    if (!BN_rand_range(random, n))
        handleErrors();
    return random;
}

unsigned char *GM::generate_random_element2(const BIGNUM *n)
{
    unsigned char *ret = new unsigned char[STR_LENGTH];
    memset(ret, 0x00, STR_LENGTH);

    strcpy((char *)ret, BN_bn2hex(generate_random_element1(n)));

    return ret;
}

void GM::KeyGen(int lambda, GM_PK &pk, GM_SK &sk)
{
    BIGNUM *p = generate_random_prime1(lambda);
    BIGNUM *q = generate_random_prime1(lambda);
    BIGNUM *p_exp = BN_new();
    BIGNUM *q_exp = BN_new();

    BIGNUM *g = BN_new();
    BIGNUM *n = BN_new();

    BIGNUM *two = BN_new();
    BIGNUM *gp = BN_new();
    BIGNUM *gq = BN_new();

    BN_dec2bn(&two, "2");

    BN_mul(n, p, q, bn_ctx);

    BN_sub(p_exp, p, BN_value_one());
    BN_sub(q_exp, q, BN_value_one());

    BN_div(p_exp, NULL, p_exp, two, bn_ctx); // p_exp = (p-1)/2
    BN_div(q_exp, NULL, q_exp, two, bn_ctx); // q_exp = (q-1)/2

    do
    { 
        g = generate_random_element1(n);

        BN_mod_exp(gp, g, p_exp, p, bn_ctx); // v = g^(n/2) mod n
        BN_mod_exp(gq, g, q_exp, q, bn_ctx); // v = g^(n/2) mod n
    } while (!BN_cmp(gp, BN_value_one()) || !BN_cmp(gq, BN_value_one())); // BN_cmp(a, b) : return 0, if a==b.

    pk.g = g;
    pk.n = n;
    sk.p = p;
    sk.q = q;
}

unsigned char *GM::Enc(const GM_PK pk, const char M){
    unsigned char *C = new unsigned char[STR_LENGTH];
    memset(C, 0x00, STR_LENGTH);

    BIGNUM *c = BN_new();
    BIGNUM *r = BN_new();
    BIGNUM *r_to_2 = BN_new();
    BIGNUM *gcd = BN_new();
    BIGNUM *two = BN_new();
    
    do
    {
        r = generate_random_element1(pk.n);

        BN_gcd(gcd, r, pk.n, bn_ctx);

    } while (BN_cmp(gcd, BN_value_one()));
   
    BN_dec2bn(&two, "2"); // 2 
    BN_mod_exp(r_to_2, r, two, pk.n, bn_ctx); // r_to_2 == r^2 

    // M == 1
    // c = g * r^2 
    if(M == '1'){
        BN_mod_mul(c, pk.g, r_to_2, pk.n, bn_ctx);
        strcpy((char *)C, BN_bn2hex(c));
    }
    // M == 0
    // c = r^2
    else
        strcpy((char *)C, BN_bn2hex(r_to_2));
    
    return C;
}



bool GM::Dec(const GM_PK pk, const GM_SK sk, const BIGNUM *c)
{
    BIGNUM *cp = BN_new();
    BIGNUM *cq = BN_new();
    BIGNUM *p_exp = BN_new();
    BIGNUM *q_exp = BN_new();
    BIGNUM *two = BN_new();
    int v1 = 0, v2 = 0;

    BN_dec2bn(&two, "2");

    // (c/p)
    BN_sub(p_exp, sk.p, BN_value_one()); 
    BN_div(p_exp, NULL, sk.p, two, bn_ctx); // p_exp = (p-1)/2
    BN_mod_exp(cp, c, p_exp, sk.p, bn_ctx);
    v1 = BN_cmp(cp, BN_value_one()); // (c/p) is QR, if v1 ==0

    // (c/q)
    BN_div(q_exp, NULL, sk.q, two, bn_ctx);
    BN_mod_exp(cq, c, q_exp, sk.q, bn_ctx);
    v2 = BN_cmp(cq, BN_value_one()); // (c/q) is QR, if v1 ==0

    if (v1 == 0 && v2 == 0) // (c/n) = (c/p)*(c/q) : QR
        return false;
    else
        return true;
}
bool GM::Dec(const GM_PK pk, const GM_SK sk, const unsigned char *C)
{
    BIGNUM *c = BN_new();

    BN_hex2bn(&c, (char *)C);

    return Dec(pk, sk, c);
}

BIGNUM *GM::XOR(const GM_PK pk, const BIGNUM *c1, const BIGNUM *c2)
{
    BIGNUM* c = BN_new();

    BN_mod_mul(c, c1, c2, pk.n, bn_ctx);

    return c;
}

unsigned char *GM::XOR(const GM_PK pk, unsigned char *C1, unsigned char *C2)
{
    BIGNUM *c1 = BN_new();
    BIGNUM *c2 = BN_new();
    unsigned char *C = new unsigned char[STR_LENGTH];

    memset(C, 0x00, STR_LENGTH);

    BN_hex2bn(&c1, (char *)C1);
    BN_hex2bn(&c2, (char *)C2);

    strcpy((char *)C, BN_bn2hex(XOR(pk, c1, c2)));

    BN_free(c1);
    BN_free(c2);

    return C;
}