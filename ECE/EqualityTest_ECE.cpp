#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <string>
#include "ECE.h"
#include "EqualityTest_ECE.h"

using namespace std;
using namespace chrono;


ECE_EqualityTest::ECE_EqualityTest(){
    this->ece = new ECE;
    aliceHexPlainText = new unsigned char[MESSAGE_HEX_SIZE];
    bobHexPlainText = new unsigned char[MESSAGE_HEX_SIZE];

    encodingTime = duration<double, milli>(0);
    step1Time = duration<double, milli>(0);
    step2Time = duration<double, milli>(0);
    step3Time = duration<double, milli>(0);
    totalTime = duration<double, milli>(0);
}

void ECE_EqualityTest::keyGen(){
    system_clock::time_point initialStartTime = system_clock::now();
    ece->KeyGen();
    system_clock::time_point initialEndTime = system_clock::now();
    initialTime = duration_cast<milliseconds>(initialEndTime - initialStartTime);
}

bool ECE_EqualityTest::equalityTest(int aliceNumber, int bobNumber){
    system_clock::time_point totalStartTime = system_clock::now();
    
    //// endcoding ////
    system_clock::time_point encodingStartTime = system_clock::now();
    stringstream stream1;
    stringstream stream2;
    stream1 << setfill('0') << setw(MESSAGE_HEX_SIZE-1) << hex << aliceNumber;
    aliceHexPlainText = reinterpret_cast<const unsigned char*>(stream1.str().c_str());
    stream2 << setfill('0') << setw(MESSAGE_HEX_SIZE-1) << hex << bobNumber;
    bobHexPlainText = reinterpret_cast<const unsigned char*>(stream2.str().c_str());
    system_clock::time_point encodingEndTime = system_clock::now();
    encodingTime += encodingEndTime - encodingStartTime;

    //// step 1 ////
    system_clock::time_point step1StartTime = system_clock::now();
    CIPHERTEXT *aliceCipherText = ece->Enc(aliceHexPlainText);             // Alice encrypts   
    system_clock::time_point step1EndTime = system_clock::now();
    step1Time += step1EndTime - step1StartTime;
    
    //// step 2 ////
    system_clock::time_point step2StartTime = system_clock::now();
    CIPHERTEXT *bobCipherText = ece->Enc(bobHexPlainText);                 // Bob encrypts
    CIPHERTEXT *subResult = ece->Sub(*bobCipherText, *aliceCipherText);    // subResult = Bob - Alice
    unsigned char *s = ece->getRandomElement();                            // scalar
    CIPHERTEXT *res = ece->Scalar_Mul(s, *subResult);                      // res = s * subResult
    system_clock::time_point step2EndTime = system_clock::now();
    step2Time += step2EndTime - step2StartTime;

    //// step 3 ////
    system_clock::time_point step3StartTime = system_clock::now();
    unsigned char *decResult = ece->Dec(*res);                             // Alice decrypts
    system_clock::time_point step3EndTime = system_clock::now();
    step3Time += step3EndTime - step3StartTime;
    system_clock::time_point totalEndTime = system_clock::now();
    totalTime += totalEndTime - totalStartTime;

    // cout << "ece: " << decResult << endl;
    if(*(decResult+1) == 48){
        // cout << "ece : same" << endl; 
        return true;
    }
    else
        return false;
}

void ECE_EqualityTest::printInitialTime(){
    cout << "EC-ElGamal Initial Time : " << initialTime.count() << "ms" << endl;
}
void ECE_EqualityTest::printEncodingTime(){
    cout << "EC-ElGamal Encoding Time : " << encodingTime.count() << "ms" << endl;
}
void ECE_EqualityTest::printStep1Time(){
    cout << "EC-ElGamal Step1 Time : " << step1Time.count() << "ms" << endl;
}
void ECE_EqualityTest::printStep2Time(){
    cout << "EC-ElGamal Step2 Time : " << step2Time.count() << "ms" << endl;
}
void ECE_EqualityTest::printStep3Time(){
    cout << "EC-ElGamal Step3 Time : " << step3Time.count() << "ms" << endl;
}
void ECE_EqualityTest::printTotalTime(){
    cout << "EC-ElGamal Total Time : " << totalTime.count() << "ms" << endl;
}