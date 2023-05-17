#include <iostream>
#include <chrono>
#include "ECE.h"

using namespace std;
using namespace chrono;

// g++ -o ece_test ECE_Test.cpp ECE.cpp -lssl -lcrypto

class ECE_EqualityTest{

    private:
        ECE *ece; 
        duration<double> encodingTime;  // random number -> message
        duration<double> initialTime;   // Alice's key generation
        duration<double> step1Time;     // Alice encrypts a message
        duration<double> step2Time;     // Bob encrypts a message, sub, scalar mul
        duration<double> step3Time;     // Alice decrypts the message
        duration<double> totalTime;     // step1~step3

    public:
        ECE_EqualityTest(){
            this->ece = new ECE;
       
        }

}