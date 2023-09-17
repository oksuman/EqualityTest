#ifndef TEST_NS_H
#define TEST_NS_H

#define MESSAGE_HEX_SIZE 10

#include <chrono>
#include "NS.h"
using namespace std;
using namespace chrono;

class NS_EqualityTest{
    private:
        NS ns; 
        NS_PK publicKey;
        NS_SK secretKey;
        const unsigned char* aliceHexPlainText;
        const unsigned char* bobHexPlainText;
        int messageHexSize;

        duration<double, milli> encodingTime;  // random number -> message
        duration<double, milli> initialTime;   // Alice's key generation
        duration<double, milli> step1Time;     // Alice encrypts a message
        duration<double, milli> step2Time;     // Bob encrypts a message, sub, scalar mul
        duration<double, milli> step3Time;     // Alice decrypts the message
        duration<double, milli> totalTime;     // step1~step3

    public:
        NS_EqualityTest();
        NS_EqualityTest(int lambda, int k, int B);
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