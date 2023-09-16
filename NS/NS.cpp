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

std::vector<NTL::ZZ> NS::pickPrimes(int k, int B){
    std::vector<NTL::ZZ> primes;
    while(primes.size() < k){
        int bitSize = getRandomBits(3, static_cast<int>(std::log2(B)));
        NTL::ZZ zzPrime;

        NTL::GenPrime(zzPrime, bitSize);

        bool isUnique = true;
        for(const NTL::ZZ& existingPrime : primes){
            if(zzPrime == existingPrime){
                isUnique = false;
                break;
            }
        }
       
        if(isUnique && zzPrime < B){
            primes.push_back(zzPrime);
        }
    }
    return primes;
}

void NS::KeyGen(NS_PK &pk, NS_SK &sk){
    // pick a family of pi of k small odd distinct primes
    sk.primes = pickPrimes(this->k, this->B);
    NTL::ZZ u(1); 
    NTL::ZZ v(1); 
    std::cout << "u : " << u << std::endl;
    std::cout << "v : " << v << std::endl;
    for (int i = 0; i < this->k; i++) {
        
        if (i < k / 2) {
            u *= sk.primes[i]; // 앞 절반은 u에 곱함
            std::cout << "u : " << u << std::endl;
            std::cout << "prime : " << sk.primes[i] << std::endl;
        } else {
            v *= sk.primes[i]; // 뒤 절반은 v에 곱함
            std::cout << "v : " << v << std::endl;
            std::cout << "prime : " << sk.primes[i] << std::endl;
        }
    }
    NTL::ZZ a,b, n;

    do{
        NTL::GenPrime(a, this->lambda/2 - NTL::NumBits(u) -1);
        a = a << 1;
        sk.p = a*u+1;
  
    }while(!NTL::ProbPrime(sk.p) || NTL::NumBits(sk.p) != this->lambda/2);
    std::cout << NTL::NumBits(sk.p) << std::endl;

    do{
        do{
            NTL::GenPrime(b, this->lambda/2 - NTL::NumBits(v));
            sk.q = 2*b*v+1;
            std::cout << NTL::NumBits(sk.q) << std::endl;   
        }while(!NTL::ProbPrime(sk.q));

        n = sk.p*sk.q;
        std::cout << "n : "<< NTL::NumBits(n) << std::endl;
    }while(NTL::NumBits(n) != this->lambda);
   

    unsigned char* hex_n = new unsigned char[lambda/8]; 
    memset(hex_n, 0x00, lambda/8);
    NTL::BytesFromZZ(hex_n, n, this->lambda/8);

    pk.n = BN_new();
    BN_hex2bn(&pk.n, (char *)hex_n);   

    NTL::ZZ pi_n = (sk.p-1)*(sk.q-1);

    do
    {
        bool usable_g = true;
        NTL::ZZ g = NTL::RandomBnd(n);
        for (int i = 0; i < this->k; i++) {
            if(NTL::PowerMod(g, sk.primes[i], n) == 1){
                usable_g = false;
                break;
            } 
        }
    } while (!usable_g);
    
    NTL::ZZ sigma = u*v;
    
    std::cout << NTL::NumBits(u) << std::endl;
    std::cout << NTL::NumBits(v) << std::endl;
    std::cout << NTL::NumBits(a) << std::endl;
    std::cout << NTL::NumBits(b) << std::endl;
    std::cout << NTL::NumBits(n) << std::endl;
}

int main(){
    NS ns = NS(3072, 30, 3072);
    NS_PK pk;
    NS_SK sk;
    ns.KeyGen(pk, sk);
    return 0;
}

// g++ NS.cpp -o NS -lssl -lcrypto -lntl -lgmp -lpthread
