#include <iostream>
#include <cstring>
#include "NS.h"

// for lambda-bits security
NS::NS(){
    bn_ctx = BN_CTX_new();
    lambda = 3072;
    k = 30;
    B = lambda;
}
NS::NS(int _lambda, int _k, int _B){
    bn_ctx = BN_CTX_new();
    this->lambda = _lambda;
    this->k = _k;
    this->B = _B;
}

NS::~NS(){
    BN_CTX_free(bn_ctx);
}

int NS::getRandomBits(int minBits, int maxBits){
    int range = maxBits - minBits +1;
    return minBits + std::rand() % range;
}

std::vector<int> NS::pickPrimes(int k, int B){
    std::vector<int> primes;
    while(primes.size() < k){
        int bitSize = getRandomBits(3, static_cast<int>(std::log2(B)));
        NTL::ZZ zzPrime;
        int intPrime;

        NTL::GenPrime(zzPrime, bitSize);
        NTL::conv(intPrime, zzPrime);
        std::cout << "bitsize : " << bitSize << std::endl; 
        std::cout << "intPrime : " << intPrime << std::endl; 


        bool isUnique = true;
        for(const int& existingPrime : primes){
            if(intPrime == existingPrime){
                isUnique = false;
                break;
            }
        }
       
        if(isUnique && intPrime < B){
            primes.push_back(intPrime);
        }
    }
    return primes;
}

void NS::KeyGen(NS_PK &pk, NS_SK &sk){
    // pick a family of pi of k small odd distinct primes
    // std::vector<int> primes;
    // pickPrimes(primes, this->k, this->B);
}

int main(){
    NS ns = NS();
    std::vector<int> primes;

    primes = ns.pickPrimes(10, 1024);


    for (const int& element : primes) {
        std::cout << element << " ";
    }
    std::cout << std::endl;
    return 0;
}

// g++ NS.cpp -o NS -lssl -lcrypto -lntl -lgmp -lpthread
