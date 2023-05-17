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

    inline void handleErrors()
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    typedef struct
    {
        BIGNUM *n, *g;
    } PK;

    typedef struct
    {
        BIGNUM *lambda, *mu;
    } SK;

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
        BIGNUM *generate_random_element1(const PK pk);
        unsigned char *generate_random_element2(const PK pk);

        void KeyGen(PK &pk, SK &sk, int lambda);

        BIGNUM * Enc(const PK pk, const BIGNUM * m);
        unsigned char * Enc(const PK pk, const unsigned char * M);

        BIGNUM *Dec(const PK pk, const SK sk, const BIGNUM *c);
        unsigned char * Dec(const PK pk, const SK sk, const unsigned char * C);

        BIGNUM * Add(const PK pk, const BIGNUM *c1, const BIGNUM * c2);
        unsigned char * Add(const PK pk, unsigned char * C1, unsigned char * C2);

        BIGNUM * Sub(const PK pk, const BIGNUM *c1, const BIGNUM * c2);
        unsigned char * Sub(const PK pk, unsigned char * C1, unsigned char * C2);
        
        BIGNUM * Scalar_Mul(const PK pk, const BIGNUM * s, const BIGNUM * c);
        unsigned char * Scalar_Mul(const PK pk, const unsigned char * S, const unsigned char * C);
    };

#ifdef __cplusplus
}
#endif

#endif