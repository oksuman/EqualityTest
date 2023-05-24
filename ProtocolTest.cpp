#include <cstdlib>
#include <iostream>
#include <random>
#include <cstdint>

#include "Paillier/EqualityTest_Paillier.h"
#include "ECE/EqualityTest_ECE.h"
#include "GM/EqualityTest_GM.h"
#include "OU/EqualityTest_OU.h"

int main(int argc, char* argv[]){

    std::random_device rd;
    std::mt19937 gen(rd());

    Paillier_EqualityTest paillierTest = Paillier_EqualityTest();
    // ECE_EqualityTest eceTest = ECE_EqualityTest();
    // GM_EqualityTest gmTest = GM_EqualityTest();
    // OU_EqualityTest ouTest = OU_EqualityTest(1024);


    std::uniform_int_distribution<std::uint16_t> dist10(0x200, 0x3FF);  
    std::uniform_int_distribution<std::uint32_t> dist30(0x40000000, 0x7FFFFFFF);

    for(int i=0; i<100; i++){
        // 10비트 정수 생성 
        std::uint16_t random10A = dist10(gen);
        std::uint16_t random10B = dist10(gen);
        paillierTest.keyGen(1536);
        paillierTest.equalityTest(random10A , random10B);
    }
    paillierTest.printEncodingTime();
    paillierTest.printInitialTime();
    paillierTest.printStep1Time();
    paillierTest.printStep2Time();
    paillierTest.printStep3Time();
    paillierTest.printTotalTime();

    
    // 30비트 정수 생성 
    // std::uint32_t random30 = dist30(gen);


    // eceTest.keyGen();
    // eceTest.equalityTest(1000 , 1000);
    // eceTest.printEncodingTime();
    // eceTest.printInitialTime();
    // eceTest.printStep1Time();
    // eceTest.printStep2Time();
    // eceTest.printStep3Time();
    // eceTest.printTotalTime();
    
    // gmTest.keyGen(1536);
    // gmTest.equalityTest(1000 , 1000);
    // gmTest.printEncodingTime();
    // gmTest.printInitialTime();
    // gmTest.printStep1Time();
    // gmTest.printStep2Time();
    // gmTest.printStep3Time();
    // gmTest.printTotalTime();

    // ouTest.keyGen();
    // ouTest.equalityTest(1000 , 1000);
    // ouTest.printEncodingTime();
    // ouTest.printInitialTime();
    // ouTest.printStep1Time();
    // ouTest.printStep2Time();
    // ouTest.printStep3Time();
    // ouTest.printTotalTime();
    return 0;
}