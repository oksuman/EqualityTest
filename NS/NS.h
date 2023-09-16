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
        BIGNUM *n, *g;
        NTL::ZZ sigma;
    } NS_PK;    

    typedef struct {
        std::vector<NTL::ZZ> primes; 
        NTL::ZZ p, q;
    } NS_SK;

    class NS{
      private:
        BN_CTX *bn_ctx;
        int lambda;  
        int k,B;
        // k : the number of primes
        // B : sigma is B-smoothe (upper bound of primes)
      public:
        NS();
        NS(int lambda, int k, int B);
        ~NS();
        int getRandomBits(int minBits, int maxBits);
        std::vector<NTL::ZZ> pickPrimes(int k ,int B);
        void KeyGen(NS_PK &pk, NS_SK &sk);
    };


#ifdef __cplusplus
}
#endif

#endif