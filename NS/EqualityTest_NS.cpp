#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <string>
#include "NS.h"
#include "EqualityTest_NS.h"

using namespace std;
using namespace chrono;


NS_EqualityTest::NS_EqualityTest() : ns(){

    encodingTime = duration<double, milli>(0);
    step1Time = duration<double, milli>(0);
    step2Time = duration<double, milli>(0);
    step3Time = duration<double, milli>(0);
    totalTime = duration<double, milli>(0);
}

NS_EqualityTest::NS_EqualityTest(int lambda, int k, int B)  : ns(lambda, k, B){

    encodingTime = duration<double, milli>(0);
    step1Time = duration<double, milli>(0);
    step2Time = duration<double, milli>(0);
    step3Time = duration<double, milli>(0);
    totalTime = duration<double, milli>(0);
}


void NS_EqualityTest::keyGen(){

    system_clock::time_point initialStartTime = system_clock::now();
    
    ns.KeyGen(this->publicKey, this->secretKey);

    system_clock::time_point initialEndTime = system_clock::now();
    initialTime = duration_cast<milliseconds>(initialEndTime - initialStartTime);

    // this->messageHexSize = this->ns.getMessageBits()/4; 
    this->messageHexSize = MESSAGE_HEX_SIZE; 
    aliceHexPlainText = new unsigned char[messageHexSize];
    bobHexPlainText = new unsigned char[messageHexSize];
}

bool NS_EqualityTest::equalityTest(int aliceNumber, int bobNumber){
    system_clock::time_point totalStartTime = system_clock::now();
    
    //// endcoding ////
    system_clock::time_point encodingStartTime = system_clock::now();
    
    // stringstream stream1;
    // stringstream stream2;
    // stream1 << setfill('0') << setw(messageHexSize-1) << hex << aliceNumber;
    // aliceHexPlainText = reinterpret_cast<const unsigned char*>(stream1.str().c_str());
    // stream2 << setfill('0') << setw(messageHexSize-1) << hex << bobNumber;
    // bobHexPlainText = reinterpret_cast<const unsigned char*>(stream2.str().c_str());
    // NTL::ZZ aliceZZText(aliceNumber);
    // NTL::ZZ bobZZText(bobNumber);
    BIGNUM *aliceBnText = BN_new();
    BIGNUM *bobBnText = BN_new();
    BN_set_word(aliceBnText, aliceNumber);
    BN_set_word(bobBnText, bobNumber);

    system_clock::time_point encodingEndTime = system_clock::now();
    encodingTime += encodingEndTime - encodingStartTime;

    //// step 1 ////
    system_clock::time_point step1StartTime = system_clock::now();
    //unsigned char* aliceCipherText = ns.Enc(publicKey, aliceHexPlainText); // Alice encrypts
    BIGNUM* aliceCipherText = ns.Enc(publicKey, aliceBnText); // Alice encrypts
    system_clock::time_point step1EndTime = system_clock::now();
    step1Time += step1EndTime - step1StartTime;
    
    //// step 2 ////
    system_clock::time_point step2StartTime = system_clock::now();
    // unsigned char* bobCipherText = ns.Enc(publicKey, bobHexPlainText);    // Bob encrypts
    // unsigned char* subResult = ns.Sub(publicKey, aliceCipherText, bobCipherText);  // subResult = Bob - Alice
    // unsigned char* s = ns.generate_random_element4(ns.getMessageBits());    // scalar
    // unsigned char* res = ns.Scalar_Mul(publicKey, s, subResult); // res = s * subResult
    
    BIGNUM* bobCipherText = ns.Enc(publicKey, bobBnText);    // Bob encrypts
    BIGNUM* subResult = ns.Sub(publicKey, aliceCipherText, bobCipherText);  // subResult = Bob - Alice
    BIGNUM* s = ns.generate_random_element3(ns.getMessageBits());    // scalar
    BIGNUM* res = ns.Scalar_Mul(publicKey, s, subResult); // res = s * subResult
    system_clock::time_point step2EndTime = system_clock::now();
    step2Time += step2EndTime - step2StartTime;

    //// step 3 ////
    system_clock::time_point step3StartTime = system_clock::now();
    // bool compareResult = ns.isZero(publicKey, secretKey, res); // Alice decrypts
    bool compareResult = ns.isZero(publicKey, secretKey, res); // Alice decrypts
    system_clock::time_point step3EndTime = system_clock::now();
    step3Time += step3EndTime - step3StartTime;
    system_clock::time_point totalEndTime = system_clock::now();
    totalTime += totalEndTime - totalStartTime;

    // std::cout << "aliceCipherText : " << BN_get_word(aliceCipherText) << std::endl;
    // std::cout << "bobCipherText : " << BN_get_word(bobCipherText) << std::endl;
    // std::cout << "subResult : " << BN_get_word(subResult) << std::endl;
    // std::cout << "s: " << BN_get_word(s) << std::endl;
    // std::cout << "res : " << BN_get_word(res) << std::endl;
    // std::cout << "g : " << BN_get_word(publicKey.g) << std::endl;
    // std::cout << "compare : " << compareResult << std::endl;
    return compareResult;
}   


void NS_EqualityTest::printInitialTime(){
    cout << "Naccache Stern Initial Time : " << initialTime.count() << "ms" << endl;
}
void NS_EqualityTest::printEncodingTime(){
    cout << "Naccache Stern Encoding Time : " << encodingTime.count() << "ms" << endl;
}
void NS_EqualityTest::printStep1Time(){
    cout << "Naccache Stern Step1 Time : " << step1Time.count() << "ms" << endl;
}
void NS_EqualityTest::printStep2Time(){
    cout << "Naccache Stern Step2 Time : " << step2Time.count() << "ms" << endl;
}
void NS_EqualityTest::printStep3Time(){
    cout << "Naccache Stern Step3 Time : " << step3Time.count() << "ms" << endl;
}
void NS_EqualityTest::printTotalTime(){
    cout << "Naccache Stern Total Time : " << totalTime.count() << "ms" << endl;
}

