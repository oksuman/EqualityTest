#ifndef TEST_PAILLIER_H
#define TEST_PAILLIER_H

#define MESSAGE_SIZE 10

#include "Paillier.h"
#include <chrono>
using namespace std;
using namespace chrono;

class Paillier_EqualityTest{
    private:
        PAILLIER paillier;
        PK publicKey;
        SK secretKey;

        const unsigned char* aliceHexPlainText;
        const unsigned char* bobHexPlainText;

        duration<double> encodingTime;  // random number -> message
        duration<double> initialTime;   // Alice's key generation
        duration<double> step1Time;     // Alice encrypts a message
        duration<double> step2Time;     // Bob encrypts a message, sub, scalar mul
        duration<double> step3Time;     // Alice decrypts the message
        duration<double> totalTime;     // step1~step3

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

