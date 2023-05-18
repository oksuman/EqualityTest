#include "Paillier/EqualityTest_Paillier.h"
#include "ECE/EqualityTest_ECE.h"
#include "GM/EqualityTest_GM.h"

int main(int argc, char* argv[]){
    Paillier_EqualityTest paillierTest = Paillier_EqualityTest();
    ECE_EqualityTest eceTest = ECE_EqualityTest();
    GM_EqualityTest gmTest = GM_EqualityTest();

    paillierTest.keyGen(1536);
    paillierTest.equalityTest(1000 , 1000);
    paillierTest.printEncodingTime();
    paillierTest.printInitialTime();
    paillierTest.printStep1Time();
    paillierTest.printStep2Time();
    paillierTest.printStep3Time();
    paillierTest.printTotalTime();

    eceTest.keyGen();
    eceTest.equalityTest(1000 , 1000);
    eceTest.printEncodingTime();
    eceTest.printInitialTime();
    eceTest.printStep1Time();
    eceTest.printStep2Time();
    eceTest.printStep3Time();
    eceTest.printTotalTime();
    
    gmTest.keyGen(1536);
    gmTest.equalityTest(1000 , 1000);
    gmTest.printEncodingTime();
    gmTest.printInitialTime();
    gmTest.printStep1Time();
    gmTest.printStep2Time();
    gmTest.printStep3Time();
    gmTest.printTotalTime();

    return 0;
}