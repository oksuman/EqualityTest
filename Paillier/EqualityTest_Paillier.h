#ifndef TEST_PAILLIER_H
#define TEST_PAILLIER_H

#define MESSAGE_HEX_SIZE 10

#include <chrono>
#include "Paillier.h"
using namespace std;
using namespace chrono;

class Paillier_EqualityTest{
    private:
        PAILLIER paillier;
        PAILLIER_PK publicKey;
        PAILLIER_SK secretKey;

        const unsigned char* aliceHexPlainText;
        const unsigned char* bobHexPlainText;

        duration<double, milli> encodingTime;  // random number -> message
        duration<double, milli> initialTime;   // Alice's key generation
        duration<double, milli> step1Time;     // Alice encrypts a message
        duration<double, milli> step2Time;     // Bob encrypts a message, sub, scalar mul
        duration<double, milli> step3Time;     // Alice decrypts the message
        duration<double, milli> totalTime;     // step1~step3
        
    public:
        Paillier_EqualityTest();
        void keyGen(int lambda);
        bool equalityTest(int aliceNumber, int bobNumber);
        void printInitialTime();
        void printEncodingTime();
        void printStep1Time();
        void printStep2Time();
        void printStep3Time();
        void printTotalTime();
};
#endif

