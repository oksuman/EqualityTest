#ifndef __NS_H__
#define __NS_H__

#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <NTL/ZZ.h>
#include <NTL/RR.h>

#include <vector>
#include <algorithm>

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

    typedef struct {
        BIGNUM *n, *g, *sigma;
        // NTL::ZZ n, g;
        // NTL::ZZ sigma;
    } NS_PK;    

    typedef struct {
        std::vector<BIGNUM *> primes; 
        BIGNUM *p, *q;
        // std::vector<NTL::ZZ> primes; 
        // NTL::ZZ p, q;
    } NS_SK;

    class NS{
      private:
        BN_CTX *bn_ctx;
        int lambda;  
        int k,B;
        int messageBits;
        // k : the number of primes
        // B : sigma is B-smoothe (upper bound of primes)
        /*
            NTL implementation : B is upper bound of primes  
            OpenSSL implementation : pick B bit primes
        */
      public:
        NS();
        NS(int lambda, int k, int B);
        ~NS();

        int getMessageBits();
        int getRandomBits(int minBits, int maxBits);
        
        std::vector<NTL::ZZ> pickPrimes(int k ,int B);
        std::vector<BIGNUM *> pickPrimes();
        
        // bnd 보다 작은 random integer
        BIGNUM *generate_random_element1(const BIGNUM *bnd);
        unsigned char * generate_random_element2(const BIGNUM *bnd);
        // bits 보다 작은 비트 수의 random integer
        BIGNUM * generate_random_element3(int bits);
        unsigned char * generate_random_element4(int bits);
        
        void KeyGen(NS_PK &pk, NS_SK &sk);

        BIGNUM* Enc(const NS_PK pk, const BIGNUM* m);
        unsigned char * Enc(const NS_PK pk, const unsigned char * M);

        BIGNUM* Dec(const NS_PK pk, const NS_SK sk, const BIGNUM* c);
        unsigned char * Dec(const NS_PK pk, const NS_SK sk, const unsigned char * C);

        BIGNUM* Add(const NS_PK pk, const BIGNUM* c1, const BIGNUM* c2);
        unsigned char * Add(const NS_PK pk, const unsigned char * C1, const unsigned char * C2);

        BIGNUM* Sub(const NS_PK pk, const BIGNUM* c1, const BIGNUM* c2);
        unsigned char * Sub(const NS_PK pk, const unsigned char * C1, const unsigned char * C2);
        

        BIGNUM* Scalar_Mul(const NS_PK pk, const BIGNUM* s, const BIGNUM* c);
        unsigned char * Scalar_Mul(const NS_PK pk, const unsigned char * S, const unsigned char * C);

        bool isZero(const NS_PK pk, const NS_SK sk, const BIGNUM* c);
        bool isZero(const NS_PK pk, const NS_SK sk, const unsigned char * C);
    };


#ifdef __cplusplus
}
#endif

#endif