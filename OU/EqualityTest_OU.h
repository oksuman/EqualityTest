#ifndef TEST_OU_H
#define TEST_OU_H

#define MESSAGE_HEX_SIZE 10

#include <chrono>
#include "OU.h"
using namespace std;
using namespace chrono;

class OU_EqualityTest{
    private:
        OU ou; 
        OU_PK publicKey;
        OU_SK secretKey;
        const unsigned char* aliceHexPlainText;
        const unsigned char* bobHexPlainText;

        duration<double> encodingTime;  // random number -> message
        duration<double> initialTime;   // Alice's key generation
        duration<double> step1Time;     // Alice encrypts a message
        duration<double> step2Time;     // Bob encrypts a message, sub, scalar mul
        duration<double> step3Time;     // Alice decrypts the message
        duration<double> totalTime;     // step1~step3

    public:
        OU_EqualityTest(int lambda);
        void keyGen();  
        bool equalityTest(int aliceNumber, int bobNumber);
        void printInitialTime();
        void printEncodingTime();
        void printStep1Time();
        void printStep2Time();
        void printStep3Time();
        void printTotalTime();
};
#endif