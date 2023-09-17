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
        // BIGNUM *n, *g;
        NTL::ZZ n, g;
        NTL::ZZ sigma;
        int messageBits;
    } NS_PK;    

    typedef struct {
        std::vector<NTL::ZZ> primes; 
        NTL::ZZ p, q;
    } NS_SK;

    class NS{
      private:
        // BN_CTX *bn_ctx;
        int lambda;  
        int k,B;
        // k : the number of primes
        // B : sigma is B-smoothe (upper bound of primes)
      public:
        NS();
        NS(int lambda, int k, int B);
        // ~NS();
        int getRandomBits(int minBits, int maxBits);
        std::vector<NTL::ZZ> pickPrimes(int k ,int B);
        void KeyGen(NS_PK &pk, NS_SK &sk);

        NTL::ZZ Enc(const NS_PK pk, const NTL::ZZ m);
        unsigned char * Enc(const NS_PK pk, const unsigned char * M);

        NTL::ZZ Dec(const NS_PK pk, const NS_SK sk, const NTL::ZZ c);
        unsigned char * Dec(const NS_PK pk, const NS_SK sk, const unsigned char * C);

        NTL::ZZ Add(const NS_PK pk, const NTL::ZZ c1, const NTL::ZZ c2);
        unsigned char * Add(const NS_PK pk, const unsigned char * C1, const unsigned char * C2);

        NTL::ZZ Sub(const NS_PK pk, const NTL::ZZ c1, const NTL::ZZ c2);
        unsigned char * Sub(const NS_PK pk, const unsigned char * C1, const unsigned char * C2);
        
        // sigma보다 작은 random nubmer
        NTL::ZZ generate_random_element1(const NS_PK pk);
        unsigned char * generate_random_element2(const NS_PK pk);

        NTL::ZZ Scalar_Mul(const NS_PK pk, const NTL::ZZ s, const NTL::ZZ c);
        unsigned char * Scalar_Mul(const NS_PK pk, const unsigned char * S, const unsigned char * C);

        bool isZero(const NS_PK pk, const NS_SK sk, const NTL::ZZ c);
        bool isZero(const NS_PK pk, const NS_SK sk, const unsigned char * C);
    };


#ifdef __cplusplus
}
#endif

#endif