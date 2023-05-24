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

void OU::set_lambda(int lambda){
    this->lambda = lambda;
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
    BIGNUM *p_2 = BN_new();                 // p^2

    pk.n = BN_new();                       
    std::cout << " 시작 "<< std::endl;
    do
    {
        sk.p = generate_random_prime1();   // p
        BN_sqr(p_2, sk.p, bn_ctx);
        sk.q = generate_random_prime1();   // q
        BN_mul(pk.n, p_2, sk.q, bn_ctx);   // n=p^2*q 
    } while (BN_num_bits(pk.n) != 3072);
    
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
    } while (!BN_cmp(g_p, BN_value_one()));
    
    BN_free(g_p);
    pk.h = BN_new();   // h = g^n mod n
    BN_mod_exp(pk.h, pk.g, pk.n, pk.n, bn_ctx);
}

BIGNUM * OU::Enc(const OU_PK pk, const BIGNUM * m){
    //c = g^m * h^r mod n
    BIGNUM *g_to_m = BN_new();
    BIGNUM *h_to_r = BN_new();
    BIGNUM *r = BN_new();   // randomly select from Zn 
    BIGNUM *c = BN_new();

    if (!BN_rand_range(r, pk.n))
        handleErrors();

    BN_mod_exp(g_to_m, pk.g, m, pk.n, bn_ctx); // g_to_m = g^m mod n
    BN_mod_exp(h_to_r, pk.h, r, pk.n, bn_ctx); // h_to_r = h^r mod n
    BN_mod_mul(c, g_to_m, h_to_r, pk.n, bn_ctx); // c = g_to_m * h_to_r mod n

    BN_free(g_to_m);
    BN_free(h_to_r);
    BN_free(r);
    
    return c;
}

unsigned char * OU::Enc(const OU_PK pk, const unsigned char * M){
    BIGNUM *m = BN_new();
    unsigned char *C = new unsigned char[3*lambda/4];
    memset(C, 0x00, 3*lambda/4);

    BN_hex2bn(&m, (char *)M);

    strcpy((char *)C, BN_bn2hex(Enc(pk, m)));

    BN_free(m);

    return C;
}

BIGNUM * OU::Dec(const OU_PK pk, const OU_SK sk, const BIGNUM *c){
    BIGNUM *m = BN_new();
    BIGNUM *p_2 = BN_new(); 
    BIGNUM *p_minus_1 = BN_new(); 

    BIGNUM *c_p = BN_new();
    BIGNUM *g_p = BN_new(); 
    BN_sqr(p_2, sk.p, bn_ctx); // p_2 = p * p
    BN_sub(p_minus_1, sk.p, BN_value_one()); // p_minus_1 = p - 1 
    BN_mod_exp(c_p, c, p_minus_1, p_2, bn_ctx); // c_p = c^(p-1) mod p^2
    BN_mod_exp(g_p, pk.g, p_minus_1, p_2, bn_ctx); // g_p = g^(p-1) mod p^2

    BIGNUM *L_c_p = BN_new(); // L(c_p)
    BIGNUM *L_g_p = BN_new(); // L(g_p)
    BIGNUM *L_g_p_inverse = BN_new(); // L(g_p)

    L_c_p = L(c_p, sk.p);
    L_g_p = L(g_p, sk.p);
    BN_mod_inverse(L_g_p_inverse, L_g_p, sk.p, bn_ctx);
    BN_mod_mul(m, L_c_p, L_g_p_inverse, sk.p, bn_ctx); // m = L_c_p / L_g_p mod p

    BN_free(p_2);
    BN_free(p_minus_1);
    BN_free(c_p);
    BN_free(g_p);
    BN_free(L_c_p);
    BN_free(L_g_p);
    BN_free(L_g_p_inverse);

    return m;
}
unsigned char * OU::Dec(const OU_PK pk, const OU_SK sk, const unsigned char * C){
    BIGNUM* c = BN_new();
    unsigned char* M = new unsigned char[lambda/4];

    memset(M, 0x00, lambda/4);

    BN_hex2bn(&c, (char*)C);

    strcpy((char*)M, BN_bn2hex(Dec(pk, sk, c)));

    return M;
}

BIGNUM * OU::Add(const OU_PK pk, const BIGNUM *c1, const BIGNUM *c2){
    BIGNUM * ret = BN_new();
    BN_mod_mul(ret, c1, c2, pk.n, bn_ctx);  // c = c1 * c2 mod n
    return ret;
}
unsigned char * OU::Add(const OU_PK pk, const unsigned char * C1, const unsigned char * C2){
    BIGNUM* c1 = BN_new();
    BIGNUM* c2 = BN_new();
    unsigned char * ret = new unsigned char[3*lambda/4];

    memset(ret, 0x00, 3*lambda/4);

    BN_hex2bn(&c1, (char*)C1);
    BN_hex2bn(&c2, (char*)C2);

    strcpy((char*)ret, BN_bn2hex(Add(pk, c1, c2)));

    BN_free(c1);
    BN_free(c2);

    return ret;
}

BIGNUM * OU::Sub(const OU_PK pk, const BIGNUM *c1, const BIGNUM *c2){
    BIGNUM *ret = BN_new();
    BIGNUM *c2_inverse  = BN_new();
    
    BN_mod_inverse(c2_inverse, c2, pk.n, bn_ctx); // c2_inverse = 1 / c2
    BN_mod_mul(ret, c1, c2_inverse, pk.n, bn_ctx);  // ret = c1 * c2_inverse mod n

    BN_free(c2_inverse);

    return ret;
}
unsigned char * OU::Sub(const OU_PK pk, const unsigned char * C1, const unsigned char * C2){
    BIGNUM* c1 = BN_new();
    BIGNUM* c2 = BN_new();
    unsigned char * ret = new unsigned char[3*lambda/4];

    memset(ret, 0x00, 3*lambda/4);


    BN_hex2bn(&c1, (char*)C1);
    BN_hex2bn(&c2, (char*)C2);

    strcpy((char*)ret, BN_bn2hex(Sub(pk, c1, c2)));

    BN_free(c1);
    BN_free(c2);

    return ret;
}

BIGNUM * OU::Scalar_Mul(const OU_PK pk, const BIGNUM *s, const BIGNUM *c){
    BIGNUM *ret = BN_new();

    BN_mod_exp(ret, c, s, pk.n, bn_ctx);

    return ret;
}
unsigned char * OU::Scalar_Mul(const OU_PK pk, const unsigned char *S, const unsigned char *C){
    BIGNUM *s = BN_new();
    BIGNUM *c = BN_new();
    unsigned char * ret = new unsigned char[3*lambda/4];

    memset(ret, 0x00, 3*lambda/4);

    BN_hex2bn(&s, (char*)S);
    BN_hex2bn(&c, (char*)C);

    strcpy((char*)ret, BN_bn2hex(Scalar_Mul(pk, s, c)));

    BN_free(s);
    BN_free(c);

    return ret;
}
