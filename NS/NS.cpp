#include <iostream>
#include <cstring>
#include "NS.h"

// for lambda-bits security
// k*B = bits of sigma (messageBits)
NS::NS(){
    bn_ctx = BN_CTX_new();
    lambda = 3072;
    // k = 10;
    // B = 32;
    k = 30;
    B = 12;
    messageBits = 256; 
}
NS::NS(int _lambda, int _k, int _B){
    bn_ctx = BN_CTX_new();
    this->lambda = _lambda;
    this->k = _k;
    this->B = _B;
    this->messageBits = _k * _B - 1;
}

NS::~NS(){
    BN_CTX_free(bn_ctx);
}

int NS::getMessageBits(){
    return this->messageBits;
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

//pick primes of fixed bit size(B)
std::vector<BIGNUM *> NS::pickPrimes(){
    std::vector<BIGNUM *> primes;
    while(primes.size() < this->k){
 
        BIGNUM *bn_prime;
        bn_prime = BN_new(); 
        BN_generate_prime_ex(bn_prime, B, 0, NULL, NULL, NULL);
        bool isUnique = true;
        for(const BIGNUM* existingPrime : primes){
            if(!BN_cmp(bn_prime, existingPrime)){
                isUnique = false;
                BN_free(bn_prime);
                break;
            }
        }
        if(isUnique){
            primes.push_back(bn_prime);
        }
    }
    return primes;
}

BIGNUM* NS::generate_random_element1(const BIGNUM* bnd){
    BIGNUM *random = BN_new();
    if (!BN_rand_range(random, bnd))
        handleErrors();
    return random;
}

unsigned char* NS::generate_random_element2(const BIGNUM* bnd){
    unsigned char * ret = new unsigned char[lambda/4];
    memset(ret, 0x00, lambda/4);
    strcpy((char*)ret, BN_bn2hex(generate_random_element1(bnd)));
    return ret;
}

BIGNUM* NS::generate_random_element3(int bits){
    BIGNUM *random = BN_new();
    int bitSize = getRandomBits(2, bits);

    if (!BN_rand(random, bitSize, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
        handleErrors();
    return random;
}

unsigned char* NS::generate_random_element4(int bits){
    unsigned char * ret = new unsigned char[lambda/4];
    memset(ret, 0x00, lambda/4);
    strcpy((char*)ret, BN_bn2hex(generate_random_element3(bits)));
    return ret;
}

void NS::KeyGen(NS_PK &pk, NS_SK &sk){
    // pick a family of pi of k small odd distinct primes
    sk.primes = pickPrimes();
    BIGNUM *u = BN_new();
    BIGNUM *v = BN_new();
    BN_one(u);
    BN_one(v);

    for (int i = 0; i < this->k; i++) {
        std::cout << "primes " << i << " : " << BN_get_word(sk.primes[i]) << std::endl;
        if (i < this->k / 2) {
            BN_mul(u, u, sk.primes[i], bn_ctx);
        } else {
            BN_mul(v, v, sk.primes[i], bn_ctx); 
        }
    }
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    sk.p = BN_new();
    sk.q = BN_new();
    pk.n = BN_new();

    do{
        // a의 비트 수 : 타켓 p 비트 수 / 2  - u 비트 수 - 1 
        BN_generate_prime_ex(a, this->lambda/2 - BN_num_bits(u) - 1, 0, NULL, NULL, NULL);
        BN_lshift1(a, a);
        BN_mul(a, u, a, bn_ctx);
        BN_add(sk.p, a, BN_value_one());

    }while(BN_num_bits(sk.p) != this->lambda/2 || !BN_is_prime_ex(sk.p, BN_prime_checks_for_size(BN_num_bits(sk.p)), bn_ctx, NULL));

    do{
        do{     
            BN_generate_prime_ex(b, this->lambda/2 - BN_num_bits(v), 0, NULL, NULL, NULL);
            BN_lshift1(b, b);
            BN_mul(b, v, b, bn_ctx);
            BN_add(sk.q, b, BN_value_one());

        }while(!BN_is_prime_ex(sk.q, BN_prime_checks_for_size(BN_num_bits(sk.q)), bn_ctx, NULL));

        BN_mul(pk.n, sk.p, sk.q, bn_ctx);
    }while(BN_num_bits(pk.n) != this->lambda);
   
    BN_free(a);
    BN_free(b);
    pk.sigma = BN_new();
    BN_mul(pk.sigma, u, v, bn_ctx);
    std::cout << "# of bits sigma : " << BN_num_bits(pk.sigma) << std::endl;
    
    BN_free(u);
    BN_free(v);

    BIGNUM *p_minus_one = BN_new();
    BIGNUM *q_minus_one = BN_new();
    BIGNUM *pi_n = BN_new();

    BN_sub(p_minus_one, sk.p, BN_value_one());
    BN_sub(q_minus_one, sk.q, BN_value_one());
    BN_mod_mul(pi_n, p_minus_one, q_minus_one, pk.n, bn_ctx);

    BN_free(p_minus_one);
    BN_free(q_minus_one);
     
    bool usable_g;
    
    BIGNUM *result = BN_new();
    BIGNUM *pi_n_over_pi = BN_new();
    BIGNUM *inv_pi = BN_new();
    
    do{
        usable_g = true;
        pk.g = this->generate_random_element1(pk.n);

        for (int i = 0; i < this->k; i++) {
            BN_mod_inverse(inv_pi, sk.primes[i], pk.n, bn_ctx);
            BN_mod_mul(pi_n_over_pi, pi_n, inv_pi, pk.n, bn_ctx);
            BN_mod_exp(result, pk.g, pi_n_over_pi, pk.n, bn_ctx);

            if(BN_is_one(result)){
                usable_g = false;
                BN_free(pk.g);
                break;
            }
        }
    } while(!usable_g);

    BN_free(pi_n);
    BN_free(result);
    BN_free(pi_n_over_pi);
    BN_free(inv_pi);
}

BIGNUM* NS::Enc(const NS_PK pk, const BIGNUM* m){
    BIGNUM *c = BN_new();
    BIGNUM *x = BN_new();
    BIGNUM *two = BN_new();

    BN_set_word(two, 2);

    do
    {
        x = this->generate_random_element1(pk.n);
    } while (BN_cmp(x, two) <= 0); 
    BN_free(two);

    BIGNUM *x_sigma = BN_new(); 
    BIGNUM *g_m = BN_new(); 
    
    BN_mod_exp(x_sigma, x, pk.sigma, pk.n, bn_ctx);
    BN_mod_exp(g_m, pk.g, m, pk.n, bn_ctx);
    BN_mod_mul(c, x_sigma, g_m, pk.n, bn_ctx);
    
    BN_free(x);
    BN_free(x_sigma);
    BN_free(g_m);
   
    return c;
}

unsigned char * NS::Enc(const NS_PK pk, const unsigned char * M){
    BIGNUM *m = BN_new();
    unsigned char* C = new unsigned char[lambda/4]; 
    memset(C, 0x00, lambda/4);

    BN_hex2bn(&m, (char *)M);

    strcpy((char *)C, BN_bn2hex(Enc(pk, m)));
  
    BN_free(m);

    return C;
}

// wrong implementation
// Exhaustive method
BIGNUM* NS::Dec(const NS_PK pk, const NS_SK sk, const BIGNUM* c){
    std::cout<<"dec"<<std::endl;
    BIGNUM* pi_n = BN_new();
    BIGNUM* p_1 = BN_new();
    BIGNUM* q_1 = BN_new();
    
    BN_mod_sub(p_1, sk.p, BN_value_one(), pk.n, bn_ctx);
    BN_mod_sub(q_1, sk.q, BN_value_one(), pk.n, bn_ctx);
    BN_mod_mul(pi_n, p_1, q_1, pk.n, bn_ctx);

    BN_free(p_1);
    BN_free(q_1);
    
    BIGNUM *inv_sigma = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *res = BN_new();

    BN_mod_inverse(inv_sigma, pk.sigma, pk.n, bn_ctx);
    BN_mod_mul(e, pi_n, inv_sigma, pk.n, bn_ctx);
    BN_mod_exp(res, c, e, pk.n, bn_ctx);

    BIGNUM* g_i = BN_new();
    BIGNUM* I = BN_new();

    // res = c^e mod n = g^m mod n
    // find i, s.t. g^i = g^m, 0<=i<=messageBits
    for(int i=0; i<INT_MAX; i++){
        BN_set_word(I, i);
        BN_mod_mul(I, I, e, pk.n, bn_ctx);
        BN_mod_exp(g_i, pk.g, I, pk.n, bn_ctx);

        if(!BN_cmp(res, g_i))
            std::cout << "dec : " << i << std::endl;
    }

    BN_free(pi_n);
    BN_free(inv_sigma);
    BN_free(e);
    return I;

}

BIGNUM* NS::Add(const NS_PK pk, const BIGNUM* c1, const BIGNUM* c2){
    BIGNUM *c = BN_new();
    BN_mod_mul(c, c1, c2, pk.n, bn_ctx);
    return c;
}

unsigned char * NS::Add(const NS_PK pk, const unsigned char * C1, const unsigned char * C2){
    BIGNUM* c1 = BN_new();
    BIGNUM* c2 = BN_new();
    unsigned char * C = new unsigned char[lambda/4];

    memset(C, 0x00, lambda/4);

    BN_hex2bn(&c1, (char*)C1);
    BN_hex2bn(&c2, (char*)C2);

    strcpy((char*)C, BN_bn2hex(Add(pk, c1, c2)));

    BN_free(c1);
    BN_free(c2);

    return C;
}

BIGNUM* NS::Sub(const NS_PK pk, const BIGNUM* c1, const BIGNUM* c2){
    BIGNUM* c = BN_new();
    BIGNUM* inv_c2 = BN_new();

    BN_mod_inverse(inv_c2, c2, pk.n, bn_ctx);
    BN_mod_mul(c, c1, inv_c2, pk.n, bn_ctx);

    BN_free(inv_c2);

    return c;
}

unsigned char * NS::Sub(const NS_PK pk, const unsigned char * C1, const unsigned char * C2){
    BIGNUM* c1 = BN_new();
    BIGNUM* c2 = BN_new();
    unsigned char * C = new unsigned char[lambda/4];

    memset(C, 0x00, lambda/4);


    BN_hex2bn(&c1, (char*)C1);
    BN_hex2bn(&c2, (char*)C2);
    
    strcpy((char*)C, BN_bn2hex(Sub(pk, c1, c2)));
    std::cout << "C : " << C << std::endl;

    BN_free(c1);
    BN_free(c2);

    return C;
}

 BIGNUM* NS::Scalar_Mul(const NS_PK pk, const  BIGNUM* s, const  BIGNUM* c){
    BIGNUM *res = BN_new();
    BN_mod_exp(res, c, s, pk.n, bn_ctx);
    return res;

}
unsigned char * NS::Scalar_Mul(const NS_PK pk, const unsigned char * S, const unsigned char * C){
    BIGNUM *s = BN_new();
    BIGNUM *c = BN_new();
    unsigned char * ret = new unsigned char[lambda/4];

    memset(ret, 0x00, lambda/4);

    BN_hex2bn(&s, (char*)S);
    BN_hex2bn(&c, (char*)C);

    strcpy((char*)ret, BN_bn2hex(Scalar_Mul(pk, s, c)));

    BN_free(s);
    BN_free(c);

    return ret;
}

bool NS::isZero(const NS_PK pk, const NS_SK sk, const BIGNUM* c){
    // decrypt with sigma 
    // But, do not solve DL problem

    BIGNUM* pi_n = BN_new();
    BIGNUM* p_1 = BN_new();
    BIGNUM* q_1 = BN_new();
    
    BN_mod_sub(p_1, sk.p, BN_value_one(), pk.n, bn_ctx);
    BN_mod_sub(q_1, sk.q, BN_value_one(), pk.n, bn_ctx);
    BN_mod_mul(pi_n, p_1, q_1, pk.n, bn_ctx);

    BN_free(p_1);
    BN_free(q_1);
    
    BIGNUM *inv_sigma = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *res = BN_new();

    BN_mod_inverse(inv_sigma, pk.sigma, pk.n, bn_ctx);


    BN_mod_mul(e, pi_n, inv_sigma, pk.n, bn_ctx);
    BN_mod_exp(res, c, e, pk.n, bn_ctx);

    BN_free(pi_n);
    BN_free(inv_sigma);
    BN_free(e);


    if(BN_is_one(res)){
        BN_free(res);
        return true;
    }
    else{
        BN_free(res);
        return false; 
    }
}

bool NS::isZero(const NS_PK pk, const NS_SK sk, const unsigned char * C){
    BIGNUM *c = BN_new();
    BN_hex2bn(&c, (char*)C);
    return isZero(pk, sk, c);
}

// g++ NS.cpp -o NS -lssl -lcrypto -lntl -lgmp -lpthread


// int main(){
//     NS ns = NS();
//     NS_PK pk;
//     NS_SK sk;
//     ns.KeyGen(pk, sk);

//     BIGNUM *aliceBnText = BN_new();
//     BIGNUM *bobBnText = BN_new();
//     BN_set_word(aliceBnText, 5);
//     BN_set_word(bobBnText, 5);

//     BIGNUM* aliceCipherText = ns.Enc(pk, aliceBnText);
//     BIGNUM* aliceDecrypt = ns.Dec(pk, sk, aliceBnText);

//     BIGNUM* bobCipherText = ns.Enc(pk, bobBnText);
//     BIGNUM* bobDecrypt = ns.Dec(pk, sk, bobBnText);

//     BIGNUM* subResult = ns.Sub(pk, aliceCipherText, bobCipherText); 
//     BIGNUM* subDecrypt = ns.Dec(pk, sk, subResult);
// }



// NTL::ZZ NS::Enc(const NS_PK pk, const NTL::ZZ m){
//     NTL::ZZ c,x;
//     do
//     {
//         x = NTL::RandomBnd(pk.n);
//     } while (x<2);
    
//     c = NTL::MulMod(NTL::PowerMod(x, pk.sigma, pk.n), NTL::PowerMod(pk.g, m, pk.n), pk.n);

//     return c;
// }

// unsigned char * NS::Enc(const NS_PK pk, const unsigned char * M){

//     unsigned char* C = new unsigned char[this->lambda/8]; 
//     memset(C, 0x00, this->lambda/8);

//     NTL::ZZ m = NTL::ZZFromBytes(M, pk.messageBits/8);
//     NTL::ZZ c = Enc(pk, m);

//     NTL::BytesFromZZ(C, c, this->lambda/8);

//     return C;
// }

// NTL::ZZ NS::Add(const NS_PK pk, const NTL::ZZ c1, const NTL::ZZ c2){
//     NTL::ZZ c = NTL::MulMod(c1, c2, pk.n);
//     return c;
// }

// unsigned char * NS::Add(const NS_PK pk, const unsigned char * C1, const unsigned char * C2){
//     NTL::ZZ c1 = NTL::ZZFromBytes(C1, this->lambda/8);
//     NTL::ZZ c2 = NTL::ZZFromBytes(C2, this->lambda/8);

//     unsigned char* C = new unsigned char[this->lambda/8]; 
//     memset(C, 0x00, this->lambda/8);

//     NTL::BytesFromZZ(C, Add(pk, c1, c2), this->lambda/8);
//     return C;
// }

// NTL::ZZ NS::Scalar_Mul(const NS_PK pk, const NTL::ZZ s, const NTL::ZZ c){
//     return NTL::PowerMod(c, s, pk.n);
// }
// unsigned char * NS::Scalar_Mul(const NS_PK pk, const unsigned char * S, const unsigned char * C){
//     NTL::ZZ c = NTL::ZZFromBytes(C, this->lambda/8);
//     NTL::ZZ s = NTL::ZZFromBytes(S, pk.messageBits/8);
    
//     unsigned char* Res = new unsigned char[this->lambda/8]; 
//     memset(Res, 0x00, this->lambda/8);
//     NTL::BytesFromZZ(Res, Scalar_Mul(pk, s, c), this->lambda/8);
    
//     return Res;
// }

// bool NS::isZero(const NS_PK pk, const NS_SK sk, const NTL::ZZ c){
//     // decrypt with sigma 
//     // But, do not solve DL problem

//     NTL::ZZ pi_n = (sk.p-1)*(sk.q-1);
//     NTL::ZZ e = NTL::MulMod(pi_n, NTL::InvMod(pk.sigma, pk.n), pk.n);
//     if(NTL::PowerMod(c, e, pk.n) == 1)
//         return true;
//     else
//         return false; 
// }

// bool NS::isZero(const NS_PK pk, const NS_SK sk, const unsigned char * C){
//     NTL::ZZ c = NTL::ZZFromBytes(C, this->lambda/8);
//     return isZero(pk, sk, c);
// }