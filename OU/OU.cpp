#include <iostream>
#include <cstring>
#include "OU.h"

OU::OU(){
    bn_ctx = BN_CTX_new();
    lambda = 1024;
}
OU::OU(int _lambda){
    bn_ctx = BN_CTX_new();
    lambda = _lambda;
}
OU::~OU(){
    BN_CTX_free(bn_ctx);
}

BIGNUM * OU::L(const BIGNUM * x, const BIGNUM * p){
    BIGNUM * ret = BN_new();
    BN_sub(ret, x, BN_value_one());
    BN_div(ret, NULL, ret, p, bn_ctx);
    return ret;
}

BIGNUM * OU::generate_random_prime1(){
    BIGNUM *prime = BN_new();
    BN_generate_prime_ex(prime, lambda, 0, NULL, NULL, NULL);
    return prime;
}
unsigned char * OU::generate_random_prime2(){
    unsigned char * ret = new unsigned char[lambda/4];
    memset(ret, 0x00, lambda/4);
    strcpy((char *)ret, BN_bn2hex(generate_random_prime1()));
    return ret;
}

BIGNUM * OU::generate_random_element1(const OU_PK pk){
    BIGNUM *random = BN_new();
    if (!BN_rand_range(random, pk.n))
        handleErrors();
    return random;
}
unsigned char * OU::generate_random_element2(const OU_PK pk){
    unsigned char * ret = new unsigned char[3*lambda/4];
    memset(ret, 0x00, 3*lambda/4);
    strcpy((char *)ret, BN_bn2hex(generate_random_element1(pk)));
    return ret;
}


void OU::KeyGen(OU_PK &pk, OU_SK &sk){
    pk.k = lambda;

    sk.p = BN_new();
    sk.q = BN_new();
    sk.p = generate_random_prime1();   // p
    sk.q = generate_random_prime1();   // q

    BIGNUM *p_2 = BN_new();                 // p^2
    BN_sqr(p_2, sk.p, bn_ctx);
    
    pk.n = BN_new();                        // n=p^2*q
    BN_mul(pk.n, p_2, sk.q, bn_ctx);
    std::cout << "n 비트 수 : "<< BN_num_bits(pk.n) << std::endl;

    pk.g = BN_new();
    BIGNUM *g_p = BN_new(); //gp = g^(p-1) mod p^2
    
    BIGNUM *p_1 = BN_new(); //p-1
    BN_sub(p_1, sk.p, BN_value_one());

    do
    {
        //random g 선택 
        if (!BN_rand_range(pk.g, pk.n))
            handleErrors();
        BN_mod_exp(g_p, pk.g, p_1, p_2, bn_ctx); 
    } while (BN_cmp(g_p, BN_value_one()));
    
    BN_free(g_p);
    pk.h = BN_new();   // h = g^n mod n
    BN_mod_exp(pk.h, pk.g, pk.n, pk.n, bn_ctx);
}

BIGNUM * OU::Enc(const OU_PK pk, const BIGNUM * m){

}
unsigned char * OU::Enc(const OU_PK pk, const unsigned char * M){

}

BIGNUM * OU::Dec(const OU_PK pk, const OU_SK sk, const BIGNUM *c){

}
unsigned char * OU::Dec(const OU_PK pk, const OU_SK sk, const unsigned char * C){

}

BIGNUM * OU::Add(const OU_PK pk, const BIGNUM *c1, const BIGNUM *c2){

}
unsigned char * OU::Add(const OU_PK pk, const unsigned char * C1, const unsigned char * C2){

}

BIGNUM * OU::Sub(const OU_PK pk, const BIGNUM *c1, const BIGNUM *c2){

}
unsigned char * OU::Sub(const OU_PK pk, const unsigned char * C1, const unsigned char * C2){

}

BIGNUM * OU::Scalar_Mul(const OU_PK pk, const BIGNUM *s, const BIGNUM *c2){

}
unsigned char * OU::Scalar_Mul(const OU_PK pk, const unsigned char *s, const unsigned char *C){
    
}
