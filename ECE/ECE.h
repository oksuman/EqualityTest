#ifndef __ECE_H__
#define __ECE_H__

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>

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
        unsigned char *C1;
        unsigned char *C2;
    } CIPHERTEXT;

    class ECE
    {
    private:
        // private key
        BIGNUM *x;

    public:
        // public key
        BN_CTX *bn_ctx;
        EC_GROUP *E;       // Elliptic curve
        const EC_POINT *G; // Generator point
        BIGNUM *q;         // order

        EC_POINT *X;

        // functions
        ECE();
        ECE(int labmda);
        ~ECE();

        void KeyGen();
        CIPHERTEXT *Enc(const unsigned char *M);
        unsigned char *Dec(const CIPHERTEXT C);

        unsigned char * getRandomElement();
        CIPHERTEXT *Scalar_Mul(const unsigned char *s, const CIPHERTEXT _C);
        CIPHERTEXT *Add(const CIPHERTEXT Ci, const CIPHERTEXT Cj);
        CIPHERTEXT *Sub(const CIPHERTEXT Ci, const CIPHERTEXT Cj);
    };

#ifdef __cplusplus
}
#endif

#endif