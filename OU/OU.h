#ifndef __OU_H__
#define __OU_H__

#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#ifdef __cplusplus
extern "C"
{
#endif
    #ifndef _HANDLE_ERRORS_
    #define _HANDLE_ERRORS_
    inline void handleErrors()
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    #endif

    typedef struct{
        int k;
        BIGNUM *n, *g, *h;
    } OU_PK;    

    typedef struct{
        BIGNUM *p, *q;
    } OU_SK;

    class OU{
      private:
        BN_CTX *bn_ctx;
        int lambda;
      public:
        OU();  
        OU(int _lambda);
        ~OU();

        void set_lambda(int lambda);
        // (x-1)/p    
        BIGNUM *L(const BIGNUM * x, const BIGNUM * p); 
        
        // len bit 소수 생성
        BIGNUM *generate_random_prime1();
        unsigned char *generate_random_prime2();

        // n보다 작은 random nubmer
        BIGNUM *generate_random_element1(const OU_PK pk);
        unsigned char *generate_random_element2(const OU_PK pk);

        void KeyGen(OU_PK &pk, OU_SK &sk);

        BIGNUM * Enc(const OU_PK pk, const BIGNUM * m);
        unsigned char * Enc(const OU_PK pk, const unsigned char * M);

        BIGNUM *Dec(const OU_PK pk, const OU_SK sk, const BIGNUM *c);
        unsigned char * Dec(const OU_PK pk, const OU_SK sk, const unsigned char * C);

        BIGNUM * Add(const OU_PK pk, const BIGNUM *c1, const BIGNUM *c2);
        unsigned char * Add(const OU_PK pk, const unsigned char * C1, const unsigned char * C2);

        BIGNUM * Sub(const OU_PK pk, const BIGNUM *c1, const BIGNUM *c2);
        unsigned char * Sub(const OU_PK pk, const unsigned char * C1, const unsigned char * C2);

        BIGNUM * Scalar_Mul(const OU_PK pk, const BIGNUM *s, const BIGNUM *c2);
        unsigned char * Scalar_Mul(const OU_PK pk, const unsigned char *s, const unsigned char *C);
    };
#ifdef __cplusplus
}
#endif

#endif