#include "Paillier/EqualityTest_Paillier.h"
// g++ -o test ProtocolTest.cpp Paillier/EqualityTest_Paillier.cpp Paillier/Paillier.cpp -lssl -lcrypto

int main(int argc, char* argv[]){
    Paillier_EqualityTest pa = Paillier_EqualityTest();
    pa.keyGen(1536);
    pa.equalityTest(1000 , 1000);
    pa.printEncodingTime();
    pa.printInitialTime();
    pa.printStep1Time();
    pa.printStep2Time();
    pa.printStep3Time();
    pa.printTotalTime();
    return 0;
}