#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <string>
#include "Paillier.h"
#include "EqualityTest_Paillier.h"

using namespace std;
using namespace chrono;

Paillier_EqualityTest::Paillier_EqualityTest(){
    aliceHexPlainText = new unsigned char[MESSAGE_HEX_SIZE];
    bobHexPlainText = new unsigned char[MESSAGE_HEX_SIZE];

    encodingTime = duration<double>(0);
    step1Time = duration<double>(0);
    step2Time = duration<double>(0);
    step3Time = duration<double>(0);
    totalTime = duration<double>(0);
}

void Paillier_EqualityTest::keyGen(int lambda){
    system_clock::time_point initialStartTime = system_clock::now();
    paillier.KeyGen(this->publicKey, this->secretKey, lambda);
    system_clock::time_point initialEndTime = system_clock::now();
    initialTime = duration_cast<milliseconds>(initialEndTime - initialStartTime);
}

bool Paillier_EqualityTest::equalityTest(int aliceNumber, int bobNumber){
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
    unsigned char *aliceCipherText = paillier.Enc(publicKey, aliceHexPlainText); // Alice encrypts
    system_clock::time_point step1EndTime = system_clock::now();
    step1Time += step1EndTime - step1StartTime;
    
    //// step 2 ////
    system_clock::time_point step2StartTime = system_clock::now();
    unsigned char *bobCipherText = paillier.Enc(publicKey, bobHexPlainText);    // Bob encrypts
    unsigned char *subResult = paillier.Sub(publicKey, aliceCipherText, bobCipherText);  // subResult = Bob - Alice
    unsigned char *s = paillier.generate_random_element2(publicKey);    // scalar
    unsigned char *res = paillier.Scalar_Mul(publicKey, s, subResult); // res = s * subResult
    system_clock::time_point step2EndTime = system_clock::now();
    step2Time += step2EndTime - step2StartTime;

    //// step 3 ////
    system_clock::time_point step3StartTime = system_clock::now();
    unsigned char* decResult = paillier.Dec(publicKey, secretKey, res); // Alice decrypts
    system_clock::time_point step3EndTime = system_clock::now();
    step3Time += step3EndTime - step3StartTime;
    system_clock::time_point totalEndTime = system_clock::now();
    totalTime += totalEndTime - totalStartTime;

    cout << "paillier : " << decResult << endl;
    if(*(decResult) == 48){
        cout << "paillier : same" << endl;
        return true;
    }
    else
        return false;
}   

void Paillier_EqualityTest::printInitialTime(){
    cout << "Paillier Initial Time : " << initialTime.count() << "ms" << endl;
}
void Paillier_EqualityTest::printEncodingTime(){
    cout << "Paillier Encoding Time : " << encodingTime.count() << "ms" << endl;
}
void Paillier_EqualityTest::printStep1Time(){
    cout << "Paillier Step1 Time : " << step1Time.count() << "ms" << endl;
}
void Paillier_EqualityTest::printStep2Time(){
    cout << "Paillier Step2 Time : " << step2Time.count() << "ms" << endl;
}
void Paillier_EqualityTest::printStep3Time(){
    cout << "Paillier Step3 Time : " << step3Time.count() << "ms" << endl;
}
void Paillier_EqualityTest::printTotalTime(){
    cout << "Paillier Total Time : " << totalTime.count() << "ms" << endl;

}

