#include <iostream>
#include <cstring>
#include "NS.h"

// for lambda-bits security
NS::NS(){
    // bn_ctx = BN_CTX_new();
    lambda = 3072;
    k = 30;
    B = lambda;
}
NS::NS(int _lambda, int _k, int _B){
    // bn_ctx = BN_CTX_new();
    this->lambda = _lambda;
    this->k = _k;
    this->B = _B;
}

// NS::~NS(){
//     BN_CTX_free(bn_ctx);
// }

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
    for (int i = 0; i < this->k; i++) {
        
        if (i < k / 2) {
            u *= sk.primes[i]; // 앞 절반은 u에 곱함
        } else {
            v *= sk.primes[i]; // 뒤 절반은 v에 곱함
        }
    }
    NTL::ZZ a,b,n;

    do{
        NTL::GenPrime(a, this->lambda/2 - NTL::NumBits(u) -1);
        a = a << 1;
        sk.p = a*u+1;
  
    }while(!NTL::ProbPrime(sk.p) || NTL::NumBits(sk.p) != this->lambda/2);

    do{
        do{
            NTL::GenPrime(b, this->lambda/2 - NTL::NumBits(v));
            sk.q = 2*b*v+1;   
        }while(!NTL::ProbPrime(sk.q));

        n = sk.p*sk.q;
    }while(NTL::NumBits(n) != this->lambda);
   

    // unsigned char* hex_n = new unsigned char[lambda/8]; 
    // memset(hex_n, 0x00, lambda/8);
    // NTL::BytesFromZZ(hex_n, n, this->lambda/8);

    pk.n = n;
    // pk.n = BN_new();
    // BN_hex2bn(&pk.n, (char *)hex_n);   

    NTL::ZZ pi_n = (sk.p-1)*(sk.q-1);

    bool usable_g;
    NTL::ZZ g;
    do{
        usable_g = true;
        g = NTL::RandomBnd(n);
        for (int i = 0; i < this->k; i++) {
            if(NTL::PowerMod(g, sk.primes[i], n) == 1){
                usable_g = false;
                break;
            } 
        }
    } while(!usable_g);
    
    NTL::ZZ sigma = u*v;
    pk.g = g;
    pk.sigma = sigma;
    pk.messageBits = NTL::NumBits(sigma)-1;

}

NTL::ZZ NS::Enc(const NS_PK pk, const NTL::ZZ m){
    NTL::ZZ c,x;
    do
    {
        x = NTL::RandomBnd(pk.n);
    } while (x<2);
    
    c = NTL::MulMod(NTL::PowerMod(x, pk.sigma, pk.n), NTL::PowerMod(pk.g, m, pk.n), pk.n);

    return c;
}

unsigned char * NS::Enc(const NS_PK pk, const unsigned char * M){

    unsigned char* C = new unsigned char[this->lambda/8]; 
    memset(C, 0x00, this->lambda/8);

    NTL::ZZ m = NTL::ZZFromBytes(M, pk.messageBits/8);
    NTL::ZZ c = Enc(pk, m);

    NTL::BytesFromZZ(C, c, this->lambda/8);

    return C;
}




NTL::ZZ NS::Add(const NS_PK pk, const NTL::ZZ c1, const NTL::ZZ c2){
    NTL::ZZ c = NTL::MulMod(c1, c2, pk.n);
    return c;
}
unsigned char * NS::Add(const NS_PK pk, const unsigned char * C1, const unsigned char * C2){
    NTL::ZZ c1 = NTL::ZZFromBytes(C1, this->lambda/8);
    NTL::ZZ c2 = NTL::ZZFromBytes(C2, this->lambda/8);

    unsigned char* C = new unsigned char[this->lambda/8]; 
    memset(C, 0x00, this->lambda/8);

    NTL::BytesFromZZ(C, Add(pk, c1, c2), this->lambda/8);
    return C;
}

NTL::ZZ NS::Sub(const NS_PK pk, const NTL::ZZ c1, const NTL::ZZ c2){
    NTL::ZZ inv_c2 = NTL::InvMod(c2, pk.n);
    NTL::ZZ c = NTL::MulMod(c1, inv_c2, pk.n);
    return c;
}
unsigned char * NS::Sub(const NS_PK pk, const unsigned char * C1, const unsigned char * C2){
    NTL::ZZ c1 = NTL::ZZFromBytes(C1, this->lambda/8);
    NTL::ZZ c2 = NTL::ZZFromBytes(C2, this->lambda/8);

    unsigned char* C = new unsigned char[this->lambda/8]; 
    memset(C, 0x00, this->lambda/8);

    NTL::BytesFromZZ(C, Sub(pk, c1, c2), this->lambda/8);
    return C;
}

// sigma보다 작은 random nubmer
NTL::ZZ NS::generate_random_element1(const NS_PK pk){
    return NTL::RandomBnd(pk.sigma);
}

unsigned char * NS::generate_random_element2(const NS_PK pk){
    unsigned char* S = new unsigned char[pk.messageBits/8]; 
    memset(S, 0x00, pk.messageBits/8);

    NTL::BytesFromZZ(S, generate_random_element1(pk), pk.messageBits/8);
    return S;
}

NTL::ZZ NS::Scalar_Mul(const NS_PK pk, const NTL::ZZ s, const NTL::ZZ c){
    return NTL::PowerMod(c, s, pk.n);
}
unsigned char * NS::Scalar_Mul(const NS_PK pk, const unsigned char * S, const unsigned char * C){
    NTL::ZZ c = NTL::ZZFromBytes(C, this->lambda/8);
    NTL::ZZ s = NTL::ZZFromBytes(S, pk.messageBits/8);
    
    unsigned char* Res = new unsigned char[this->lambda/8]; 
    memset(Res, 0x00, this->lambda/8);
    NTL::BytesFromZZ(Res, Scalar_Mul(pk, s, c), this->lambda/8);
    
    return Res;
}

bool NS::isZero(const NS_PK pk, const NS_SK sk, const NTL::ZZ c){
    // decrypt with sigma 
    // But, do not solve DL problem

    NTL::ZZ pi_n = (sk.p-1)*(sk.q-1);
    NTL::ZZ e = NTL::MulMod(pi_n, NTL::InvMod(pk.sigma, pk.n), pk.n);
    if(NTL::PowerMod(c, e, pk.n) == 1)
        return true;
    else
        return false; 
}

bool NS::isZero(const NS_PK pk, const NS_SK sk, const unsigned char * C){
    NTL::ZZ c = NTL::ZZFromBytes(C, this->lambda/8);
    return isZero(pk, sk, c);
}

// int main(){
//     NS ns = NS(3072, 30, 3072);
//     NS_PK pk;
//     NS_SK sk;
//     ns.KeyGen(pk, sk);

//     NTL::ZZ a1(11669);
//     NTL::ZZ b1(11669);

//     NTL::ZZ a2(1506);
//     NTL::ZZ b2(6051);

//     NTL::ZZ ca1 = ns.Enc(pk, a1);
//     NTL::ZZ cb1 = ns.Enc(pk, b1);

//     NTL::ZZ ca2 = ns.Enc(pk, a2);
//     NTL::ZZ cb2 = ns.Enc(pk, b2);

//     NTL::ZZ s = ns.generate_random_element1(pk);
    
//     NTL::ZZ sub1 = ns.Sub(pk, ca1, cb1);
//     NTL::ZZ sub2 = ns.Sub(pk, ca2, cb2);

//     NTL::ZZ smul1 = ns.Scalar_Mul(pk, s, sub1);
//     NTL::ZZ smul2 = ns.Scalar_Mul(pk, s, sub2);

//     bool res1 = ns.isZero(pk, sk, smul1);
//     bool res2 = ns.isZero(pk, sk, smul2);

//     std::cout << "s : " << s << std::endl; 
//     std::cout << "sub1 : " << sub1 << std::endl;
//     std::cout << "sub2 : " << sub2 << std::endl;
//     std::cout << "smul1 : " << smul1 << std::endl;
//     std::cout << "smul2 : " << smul2 << std::endl;
//     std::cout << "res1 : " << res1 << std::endl;
//     std::cout << "res2 : " << res2 << std::endl;

//     return 0;
// }

// g++ NS.cpp -o NS -lssl -lcrypto -lntl -lgmp -lpthread
