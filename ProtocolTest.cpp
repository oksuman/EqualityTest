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

int main(int argc, char* argv[]){

    std::random_device rd;
    std::mt19937 gen(rd());

    Paillier_EqualityTest paillierTest = Paillier_EqualityTest();
    ECE_EqualityTest eceTest = ECE_EqualityTest();
    GM_EqualityTest gmTest = GM_EqualityTest();
    OU_EqualityTest ouTest = OU_EqualityTest(1024);


    std::uniform_int_distribution<std::uint16_t> dist10(0x200, 0x3FF);  
    std::uniform_int_distribution<std::uint32_t> dist30(0x40000000, 0x7FFFFFFF);


    int gmEqualCount = 0;
    int paillierEqualCount = 0;
    int eceEqualCount = 0;
    int ouEqualCount = 0;

    std::vector<std::uint16_t> gmList;
    std::vector<std::uint16_t> paillierListA;
    std::vector<std::uint16_t> paillierListB;
    std::vector<std::uint16_t> eceList;
    std::vector<std::uint16_t> ouListA;
    std::vector<std::uint16_t> ouListB;

    std::vector<std::uint16_t> exactList;

    gmTest.keyGen(1536);
    paillierTest.keyGen(1536);
    eceTest.keyGen();
    ouTest.keyGen();

    
    for(int i=0; i<1000; i++){
        // 10비트 정수 생성 
        std::uint16_t random10A = dist10(gen);
        std::uint16_t random10B = dist10(gen);
        if(random10A == random10B){
            exactList.push_back(random10A);
        }
        if(gmTest.equalityTest(random10A , random10B)){
            gmList.push_back(random10A);
            gmEqualCount++;
        }
        if(paillierTest.equalityTest(random10A , random10B)){
            paillierListA.push_back(random10A);
            paillierListB.push_back(random10B);
            paillierEqualCount++;
        }
        if(eceTest.equalityTest(random10A , random10B)){
            eceList.push_back(random10A);
            eceEqualCount++;
        }
        if(ouTest.equalityTest(random10A , random10B)){
            ouListA.push_back(random10A);
            ouListB.push_back(random10B);
            ouEqualCount++;
        }
    }
    std::cout << "exact : ";
    std::copy(exactList.begin(), exactList.end(), std::ostream_iterator<std::uint16_t>(std::cout, " "));
    std::cout << std::endl;
    
    std::cout << "gm : ";
    std::copy(gmList.begin(), gmList.end(), std::ostream_iterator<std::uint16_t>(std::cout, " "));
    std::cout << std::endl;

    std::cout << "paillierA : ";
    std::copy(paillierListA.begin(), paillierListA.end(), std::ostream_iterator<std::uint16_t>(std::cout, " "));
    std::cout << std::endl;
    std::cout << "paillierB : ";
    std::copy(paillierListB.begin(), paillierListB.end(), std::ostream_iterator<std::uint16_t>(std::cout, " "));
    std::cout << std::endl;
    
    std::cout << "ece : ";
    std::copy(eceList.begin(), eceList.end(), std::ostream_iterator<std::uint16_t>(std::cout, " "));
    std::cout << std::endl;
    
    std::cout << "ou A : ";
    std::copy(ouListA.begin(), ouListA.end(), std::ostream_iterator<std::uint16_t>(std::cout, " "));
    std::cout << std::endl;
    std::cout << "ou B : ";
    std::copy(ouListB.begin(), ouListB.end(), std::ostream_iterator<std::uint16_t>(std::cout, " "));
    std::cout << std::endl;
    

    gmTest.printEncodingTime();
    gmTest.printInitialTime();
    gmTest.printStep1Time();
    gmTest.printStep2Time();
    gmTest.printStep3Time();
    gmTest.printTotalTime();

    paillierTest.printEncodingTime();
    paillierTest.printInitialTime();
    paillierTest.printStep1Time();
    paillierTest.printStep2Time();
    paillierTest.printStep3Time();
    paillierTest.printTotalTime();

    eceTest.printEncodingTime();
    eceTest.printInitialTime();
    eceTest.printStep1Time();
    eceTest.printStep2Time();
    eceTest.printStep3Time();
    eceTest.printTotalTime();

    ouTest.printEncodingTime();
    ouTest.printInitialTime();
    ouTest.printStep1Time();
    ouTest.printStep2Time();
    ouTest.printStep3Time();
    ouTest.printTotalTime();

    cout << "gm : " << gmEqualCount << endl;
    cout << "paillier : " << paillierEqualCount << endl;
    cout << "ece : " << eceEqualCount << endl;
    cout << "ou : " << ouEqualCount << endl;
    
    // 30비트 정수 생성 
    // std::uint32_t random30 = dist30(gen);


    return 0;
}