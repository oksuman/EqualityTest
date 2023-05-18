#ifndef __PAILLIER_H__
#define __PAILLIER_H__

#define STR_LENGTH 1536

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
    
    typedef struct
    {
        BIGNUM *n, *g;
    } PAILLIER_PK;

    typedef struct
    {
        BIGNUM *lambda, *mu;
    } PAILLIER_SK;

    class PAILLIER
    {
    private:
        BN_CTX *bn_ctx;

    public:


        // functions
        PAILLIER();
        PAILLIER(int labmda);
        ~PAILLIER();

        BIGNUM *L(const BIGNUM * x, const BIGNUM * n);        
        BIGNUM *generate_random_prime1(int len);
        unsigned char *generate_random_prime2(int len);
        BIGNUM *generate_random_element1(const PAILLIER_PK pk);
        unsigned char *generate_random_element2(const PAILLIER_PK pk);

        void KeyGen(PAILLIER_PK &pk, PAILLIER_SK &sk, int lambda);

        BIGNUM * Enc(const PAILLIER_PK pk, const BIGNUM * m);
        unsigned char * Enc(const PAILLIER_PK pk, const unsigned char * M);

        BIGNUM *Dec(const PAILLIER_PK pk, const PAILLIER_SK sk, const BIGNUM *c);
        unsigned char * Dec(const PAILLIER_PK pk, const PAILLIER_SK sk, const unsigned char * C);

        BIGNUM * Add(const PAILLIER_PK pk, const BIGNUM *c1, const BIGNUM * c2);
        unsigned char * Add(const PAILLIER_PK pk, unsigned char * C1, unsigned char * C2);

        BIGNUM * Sub(const PAILLIER_PK pk, const BIGNUM *c1, const BIGNUM * c2);
        unsigned char * Sub(const PAILLIER_PK pk, unsigned char * C1, unsigned char * C2);
        
        BIGNUM * Scalar_Mul(const PAILLIER_PK pk, const BIGNUM * s, const BIGNUM * c);
        unsigned char * Scalar_Mul(const PAILLIER_PK pk, const unsigned char * S, const unsigned char * C);
    };

#ifdef __cplusplus
}
#endif

#endif