#ifndef TEST_GM_H
#define TEST_GM_H

#define MESSAGE_BIN_SIZE 40

#include <chrono>
#include <string>
#include "GM.h"
using namespace std;
using namespace chrono;

class GM_EqualityTest{
    private:
        GM gm; 

        GM_PK publicKey;
        GM_SK secretKey;
        string aliceBinPlainText;
        string bobBinPlainText;

        duration<double> encodingTime;  // random number -> message
        duration<double> initialTime;   // Alice's key generation
        duration<double> step1Time;     // Alice encrypts a message
        duration<double> step2Time;     // Bob encrypts a message, sub, scalar mul
        duration<double> step3Time;     // Alice decrypts the message
        duration<double> totalTime;     // step1~step3

    public:
        GM_EqualityTest();
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