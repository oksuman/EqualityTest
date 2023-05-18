// g++ -o Paillier Paillier.cpp -lssl -lcrypto

#include <iostream>
#include <cstring>
#include "Paillier.h"

BIGNUM *PAILLIER::generate_random_prime1(int len = 1024)
{
    BIGNUM *prime = BN_new();
    BN_generate_prime_ex(prime, len, 0, NULL, NULL, NULL);
    return prime;
}

unsigned char * PAILLIER::generate_random_prime2(int len = 1024)
{
    unsigned char * ret = new unsigned char[STR_LENGTH];
    memset(ret, 0x00, STR_LENGTH);
    
    strcpy((char *)ret, BN_bn2hex(generate_random_prime1(len)));

    return ret;
}

BIGNUM *PAILLIER::generate_random_element1(const PAILLIER_PK pk)
{
    BIGNUM *random = BN_new();
    if (!BN_rand_range(random, pk.n))
        handleErrors();
    return random;
}

unsigned char * PAILLIER::generate_random_element2(const PAILLIER_PK pk)
{
    unsigned char * ret = new unsigned char[STR_LENGTH];
    memset(ret, 0x00, STR_LENGTH);
    
    strcpy((char *)ret, BN_bn2hex(generate_random_element1(pk)));

    return ret;
}

PAILLIER::PAILLIER()
{
    bn_ctx = BN_CTX_new();
}

PAILLIER::~PAILLIER()
{
    BN_CTX_free(bn_ctx);
}
void PAILLIER::KeyGen(PAILLIER_PK &pk, PAILLIER_SK &sk, int lambda)
{
    BIGNUM *p = generate_random_prime1(lambda);
    BIGNUM *q = generate_random_prime1(lambda);
    BIGNUM *n_2 = BN_new();

    pk.n = BN_new();
    pk.g = BN_new();
    sk.lambda = BN_new();
    sk.mu = BN_new();
    BN_mul(pk.n, p, q, bn_ctx);
    BN_add(pk.g, pk.n, BN_value_one());

    BN_sub(p, p, BN_value_one()); // p = p-1
    BN_sub(q, q, BN_value_one()); // q = q-1

    BN_mul(sk.lambda, p, q, bn_ctx);
    BN_sqr(n_2, pk.n, bn_ctx);

    BIGNUM *g_lambda = BN_new();
    BIGNUM *L_g_lambda = BN_new();

    BN_mod_exp(g_lambda, pk.g, sk.lambda, n_2, bn_ctx);

    BN_sub(L_g_lambda, g_lambda, BN_value_one());
    BN_div(L_g_lambda, NULL, L_g_lambda, pk.n, bn_ctx);
    BN_mod_inverse(sk.mu, L_g_lambda, pk.n, bn_ctx);
}


BIGNUM * PAILLIER::Enc(const PAILLIER_PK pk, const BIGNUM * m)
{
    BIGNUM *n_2 = BN_new();
    BIGNUM *g_to_m = BN_new();
    BIGNUM *r_to_n = BN_new();
    BIGNUM *r = BN_new();    
    BIGNUM *c = BN_new();

    if (!BN_rand_range(r, pk.n))
        handleErrors();

    BN_sqr(n_2, pk.n, bn_ctx); // n_2 = n * n
    BN_mod_exp(g_to_m, pk.g, m, n_2, bn_ctx); // g_to_m = g^m mod n_2
    BN_mod_exp(r_to_n, r, pk.n, n_2, bn_ctx); // r_to_n = r^n mod n_2
    BN_mod_mul(c, g_to_m, r_to_n, n_2, bn_ctx); // c = g_to_m * r_to_m mod n_2

    BN_free(n_2);
    BN_free(g_to_m);
    BN_free(r_to_n);
    BN_free(r);

    return c;
}

unsigned char *PAILLIER::Enc(const PAILLIER_PK pk, const unsigned char *M)
{
    BIGNUM *m = BN_new();
    unsigned char *C = new unsigned char[STR_LENGTH];

    memset(C, 0x00, STR_LENGTH);

    BN_hex2bn(&m, (char *)M);

    strcpy((char *)C, BN_bn2hex(Enc(pk, m)));

    BN_free(m);

    return C;
}

BIGNUM * PAILLIER::Dec(const PAILLIER_PK pk, const PAILLIER_SK sk, const BIGNUM* c)
{
    BIGNUM *m = BN_new();
    BIGNUM *c_lambda = BN_new();
    BIGNUM *n_2 = BN_new();

    BN_sqr(n_2, pk.n, bn_ctx); // n_2 = n * n

    BN_mod_exp(c_lambda, c, sk.lambda, n_2, bn_ctx); // c_lambda = C^labmda mod n_2
    c_lambda = L(c_lambda, pk.n);                    // L(c_lambda)

    BN_mod_mul(m, c_lambda, sk.mu, pk.n, bn_ctx); // m = L(c_lambda) * mu mod n

    BN_free(c_lambda);
    BN_free(n_2);
    
    return m;
}
unsigned char * PAILLIER::Dec(const PAILLIER_PK pk, const PAILLIER_SK sk, const unsigned char* C)
{
    BIGNUM* c = BN_new();
    unsigned char* M = new unsigned char[STR_LENGTH];

    memset(M, 0x00, STR_LENGTH);

    BN_hex2bn(&c, (char*)C);

    strcpy((char*)M, BN_bn2hex(Dec(pk, sk, c)));

    return M;
}

BIGNUM * PAILLIER::L(const BIGNUM * x, const BIGNUM * n)
{
    BIGNUM * ret = BN_new();

    BN_sub(ret, x, BN_value_one());
    BN_div(ret, NULL, ret, n, bn_ctx);

    return ret;
}


BIGNUM * PAILLIER::Add(const PAILLIER_PK pk, const BIGNUM *c1, const BIGNUM * c2)
{
    BIGNUM * ret = BN_new();
    BIGNUM * n_2 = BN_new();

    BN_sqr(n_2, pk.n, bn_ctx); // n_2 = n * n

    BN_mod_mul(ret, c1, c2, n_2, bn_ctx);  // c = c1 * c2 mod n_2

    BN_free(n_2);

    return ret;
}

unsigned char * PAILLIER::Add(const PAILLIER_PK pk, unsigned char * C1, unsigned char * C2)
{
    BIGNUM* c1 = BN_new();
    BIGNUM* c2 = BN_new();
    unsigned char * ret = new unsigned char[STR_LENGTH];

    memset(ret, 0x00, STR_LENGTH);


    BN_hex2bn(&c1, (char*)C1);
    BN_hex2bn(&c2, (char*)C2);

    strcpy((char*)ret, BN_bn2hex(Add(pk, c1, c2)));

    BN_free(c1);
    BN_free(c2);

    return ret;
}

// c1 - c2 
BIGNUM * PAILLIER::Sub(const PAILLIER_PK pk, const BIGNUM *c1, const BIGNUM * c2)
{
    BIGNUM * ret = BN_new();
    BIGNUM * n_2 = BN_new();

    BIGNUM * r_c2  = BN_new();
    BN_sqr(n_2, pk.n, bn_ctx); // n_2 = n * n

    BN_mod_inverse(r_c2, c2, n_2, bn_ctx); // r_c2 = 1 / c2

    BN_mod_mul(ret, c1, r_c2, n_2, bn_ctx);  // ret = c1 * r_c2 mod n_2

    BN_free(r_c2);
    BN_free(n_2);

    return ret;
}

unsigned char * PAILLIER::Sub(const PAILLIER_PK pk, unsigned char * C1, unsigned char * C2)
{
    BIGNUM* c1 = BN_new();
    BIGNUM* c2 = BN_new();
    unsigned char * ret = new unsigned char[STR_LENGTH];

    memset(ret, 0x00, STR_LENGTH);


    BN_hex2bn(&c1, (char*)C1);
    BN_hex2bn(&c2, (char*)C2);

    strcpy((char*)ret, BN_bn2hex(Sub(pk, c1, c2)));

    BN_free(c1);
    BN_free(c2);

    return ret;
}



BIGNUM * PAILLIER::Scalar_Mul(const PAILLIER_PK pk, const BIGNUM * s, const BIGNUM * c)
{
    BIGNUM *ret = BN_new();
    BIGNUM *n_2 = BN_new();

    BN_sqr(n_2, pk.n, bn_ctx);

    BN_mod_exp(ret, c, s, n_2, bn_ctx);

    BN_free(n_2);

    return ret;
}

unsigned char * PAILLIER::Scalar_Mul(const PAILLIER_PK pk, const unsigned char * S, const unsigned char * C)
{
    BIGNUM *s = BN_new();
    BIGNUM *c = BN_new();
    unsigned char * ret = new unsigned char[STR_LENGTH];

    memset(ret, 0x00, STR_LENGTH);

    BN_hex2bn(&s, (char*)S);
    BN_hex2bn(&c, (char*)C);

    strcpy((char*)ret, BN_bn2hex(Scalar_Mul(pk, s, c)));

    BN_free(s);
    BN_free(c);

    return ret;
}