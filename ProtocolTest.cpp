#include <cstdlib>
#include <iostream>
#include <random>
#include <cstdint>
#include <vector>
#include <iterator>
#include "Paillier/EqualityTest_Paillier.h"
#include "ECE/EqualityTest_ECE.h"
#include "GM/EqualityTest_GM.h"
#include "OU/EqualityTest_OU.h"
#include "NS/EqualityTest_NS.h"

int main(int argc, char* argv[]){

    std::random_device rd;
    std::mt19937 gen(rd());

    // n : 3072bit, eliptic curve : 256
    Paillier_EqualityTest paillierTest = Paillier_EqualityTest();
    ECE_EqualityTest eceTest = ECE_EqualityTest();
    GM_EqualityTest gmTest = GM_EqualityTest();
    OU_EqualityTest ouTest = OU_EqualityTest();
    NS_EqualityTest nsTest = NS_EqualityTest();


    std::uniform_int_distribution<std::uint16_t> dist10(0x200, 0x3FF);  
    std::uniform_int_distribution<std::uint32_t> dist30(0x40000000, 0x7FFFFFFF);


    int gmEqualCount = 0;
    int paillierEqualCount = 0;
    int eceEqualCount = 0;
    int ouEqualCount = 0;
    int nsEqualCount = 0;

    std::vector<std::uint16_t> gmList;
    std::vector<std::uint16_t> paillierListA;
    std::vector<std::uint16_t> paillierListB;
    std::vector<std::uint16_t> eceList;
    std::vector<std::uint16_t> ouListA;
    std::vector<std::uint16_t> ouListB;
    std::vector<std::uint16_t> nsListA;
    std::vector<std::uint16_t> nsListB;

    std::vector<std::uint16_t> exactList;

    // 128bit security only 
    gmTest.keyGen(1536);
    paillierTest.keyGen(1536);
    eceTest.keyGen();
    ouTest.keyGen();
    nsTest.keyGen();


    for(int i=0; i<1000; i++){
        // 10비트 정수 생성 
        std::uint16_t random10A = dist10(gen);
        std::uint16_t random10B = dist10(gen);
        // std::uint16_t random10A = 110;
        // std::uint16_t random10B = 110;
        if(random10A == random10B){
            exactList.push_back(random10A);
        }
        // if(gmTest.equalityTest(random10A , random10B)){
        //     gmList.push_back(random10A);
        //     gmEqualCount++;
        // }
        // if(paillierTest.equalityTest(random10A , random10B)){
        //     paillierListA.push_back(random10A);
        //     paillierListB.push_back(random10B);
        //     paillierEqualCount++;
        // }
        if(eceTest.equalityTest(random10A , random10B)){
            eceList.push_back(random10A);
            eceEqualCount++;
        }
        if(ouTest.equalityTest(random10A , random10B)){
            ouListA.push_back(random10A);
            ouListB.push_back(random10B);
            ouEqualCount++;
        }
        if(nsTest.equalityTest(random10A , random10B)){
            nsListA.push_back(random10A);
            nsListB.push_back(random10B);
            nsEqualCount++;
        }
    }
    std::cout << "exact : ";
    std::copy(exactList.begin(), exactList.end(), std::ostream_iterator<std::uint16_t>(std::cout, " "));
    std::cout << std::endl;
    
    // std::cout << "gm : ";
    // std::copy(gmList.begin(), gmList.end(), std::ostream_iterator<std::uint16_t>(std::cout, " "));
    // std::cout << std::endl;

    // std::cout << "paillierA : ";
    // std::copy(paillierListA.begin(), paillierListA.end(), std::ostream_iterator<std::uint16_t>(std::cout, " "));
    // std::cout << std::endl;
    // std::cout << "paillierB : ";
    // std::copy(paillierListB.begin(), paillierListB.end(), std::ostream_iterator<std::uint16_t>(std::cout, " "));
    // std::cout << std::endl;
    
    std::cout << "ece : ";
    std::copy(eceList.begin(), eceList.end(), std::ostream_iterator<std::uint16_t>(std::cout, " "));
    std::cout << std::endl;
    
    std::cout << "ou A : ";
    std::copy(ouListA.begin(), ouListA.end(), std::ostream_iterator<std::uint16_t>(std::cout, " "));
    std::cout << std::endl;
    std::cout << "ou B : ";
    std::copy(ouListB.begin(), ouListB.end(), std::ostream_iterator<std::uint16_t>(std::cout, " "));
    std::cout << std::endl;
    
    std::cout << "ns A : ";
    std::copy(nsListA.begin(), nsListA.end(), std::ostream_iterator<std::uint16_t>(std::cout, " "));
    std::cout << std::endl;
    std::cout << "ns B : ";
    std::copy(nsListB.begin(), nsListB.end(), std::ostream_iterator<std::uint16_t>(std::cout, " "));
    std::cout << std::endl;

    gmTest.printEncodingTime();
    gmTest.printInitialTime();
    gmTest.printStep1Time();
    gmTest.printStep2Time();
    gmTest.printStep3Time();
    gmTest.printTotalTime();
    std::cout << std::endl;
    paillierTest.printEncodingTime();
    paillierTest.printInitialTime();
    paillierTest.printStep1Time();
    paillierTest.printStep2Time();
    paillierTest.printStep3Time();
    paillierTest.printTotalTime();
    std::cout << std::endl;
    eceTest.printEncodingTime();
    eceTest.printInitialTime();
    eceTest.printStep1Time();
    eceTest.printStep2Time();
    eceTest.printStep3Time();
    eceTest.printTotalTime();
    std::cout << std::endl;
    ouTest.printEncodingTime();
    ouTest.printInitialTime();
    ouTest.printStep1Time();
    ouTest.printStep2Time();
    ouTest.printStep3Time();
    ouTest.printTotalTime();
    std::cout << std::endl;
    nsTest.printEncodingTime();
    nsTest.printInitialTime();
    nsTest.printStep1Time();
    nsTest.printStep2Time();
    nsTest.printStep3Time();
    nsTest.printTotalTime();
    std::cout << std::endl;
    std::cout << "gm : " << gmEqualCount << endl;
    std::cout << "paillier : " << paillierEqualCount << endl;
    std::cout << "ece : " << eceEqualCount << endl;
    std::cout << "ou : " << ouEqualCount << endl;
    std::cout << "ns : " << nsEqualCount << endl;
    
    // 30비트 정수 생성 
    // std::uint32_t random30 = dist30(gen);


    return 0;
}