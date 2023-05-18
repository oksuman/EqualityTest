#ifndef __GM_H__
#define __GM_H__

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
    } GM_PK;

    typedef struct
    {
        BIGNUM *p, *q;
    } GM_SK;

    class GM
    {
    private:
        BN_CTX *bn_ctx;

    public:
        // functions
        GM();
        GM(int labmda);
        ~GM();

        BIGNUM *generate_random_prime1(int len);
        unsigned char *generate_random_prime2(int len);

        BIGNUM *generate_random_element1(const BIGNUM *n);
        unsigned char *generate_random_element2(const BIGNUM *n);

        void KeyGen(int lambda, GM_PK &pk, GM_SK &sk);

        BIGNUM *Enc(const GM_PK pk, const BIGNUM *m);
        unsigned char *Enc(const GM_PK pk, const char M);

        bool Dec(const GM_PK pk, const GM_SK sk, const BIGNUM *c);
        bool Dec(const GM_PK pk, const GM_SK sk, const unsigned char *C);

        BIGNUM *XOR(const GM_PK pk, const BIGNUM *c1, const BIGNUM *c2);
        unsigned char *XOR(const GM_PK pk, unsigned char *C1, unsigned char *C2);
    };

#ifdef __cplusplus
}
#endif

#endif