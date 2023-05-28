#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <string>
#include <bitset>
#include <array>
#include <algorithm>
#include <random>
#include "GM.h"
#include "EqualityTest_GM.h"

using namespace std;
using namespace chrono;

GM_EqualityTest::GM_EqualityTest(){
    
    encodingTime = duration<double, milli>(0);
    step1Time = duration<double, milli>(0);
    step2Time = duration<double, milli>(0);
    step3Time = duration<double, milli>(0);
    totalTime = duration<double, milli>(0);
}

void GM_EqualityTest::keyGen(int lambda){
    system_clock::time_point initialStartTime = system_clock::now();
    gm.KeyGen(lambda, this->publicKey, this->secretKey);
    system_clock::time_point initialEndTime = system_clock::now();
    initialTime = duration_cast<milliseconds>(initialEndTime - initialStartTime);
}

bool GM_EqualityTest::equalityTest(int aliceNumber, int bobNumber){
    system_clock::time_point totalStartTime = system_clock::now();
    
    //// endcoding ////
    system_clock::time_point encodingStartTime = system_clock::now();
    string aliceBinPlainText = bitset<MESSAGE_BIN_SIZE>(aliceNumber).to_string();
    string bobBinPlainText = bitset<MESSAGE_BIN_SIZE>(bobNumber).to_string();
    system_clock::time_point encodingEndTime = system_clock::now();
    encodingTime += encodingEndTime - encodingStartTime;

    //// step 1 ////
    system_clock::time_point step1StartTime = system_clock::now();
    array<unsigned char*, MESSAGE_BIN_SIZE> aliceCipherText;
    int index = 0;
    for(char m : aliceBinPlainText){
        aliceCipherText[index] = gm.Enc(publicKey, m);
        index++;
    }
    system_clock::time_point step1EndTime = system_clock::now();
    step1Time += step1EndTime - step1StartTime;

    //// step 2 ////
    system_clock::time_point step2StartTime = system_clock::now();
    array<unsigned char*, MESSAGE_BIN_SIZE> bobCipherText;
    index = 0;
    for(char m : bobBinPlainText){
        bobCipherText[index] = gm.Enc(publicKey, m);
        index++;
    }
    array<unsigned char*, MESSAGE_BIN_SIZE> xorCipherText;
    for(index=0; index<MESSAGE_BIN_SIZE; index++){
        xorCipherText[index] = gm.XOR(publicKey, aliceCipherText[index], bobCipherText[index]);
    }
    unsigned seed = system_clock::now().time_since_epoch().count();
    shuffle(xorCipherText.begin(), xorCipherText.end(), default_random_engine(seed));
    system_clock::time_point step2EndTime = system_clock::now();
    step2Time += step2EndTime - step2StartTime;

    //// step 3 ////
    system_clock::time_point step3StartTime = system_clock::now();
    bitset<MESSAGE_BIN_SIZE>decResult;
    for(index=0; index<MESSAGE_BIN_SIZE; index++){
        decResult.set(MESSAGE_BIN_SIZE - index - 1, gm.Dec(publicKey, secretKey, xorCipherText[index]));
    }
    system_clock::time_point step3EndTime = system_clock::now();
    step3Time += step3EndTime - step3StartTime;
    system_clock::time_point totalEndTime = system_clock::now();
    totalTime += totalEndTime - totalStartTime;

    // cout << "gm : " << decResult << endl;
    // cout << "alice m : " << aliceBinPlainText << endl;
    // cout << "bob m : " << bobBinPlainText << endl;
    bitset<MESSAGE_BIN_SIZE>AdecResult;
    for(index=0; index<MESSAGE_BIN_SIZE; index++){
        AdecResult.set(MESSAGE_BIN_SIZE - index - 1, gm.Dec(publicKey, secretKey, aliceCipherText[index]));
    }
    bitset<MESSAGE_BIN_SIZE>BdecResult;
    for(index=0; index<MESSAGE_BIN_SIZE; index++){
        BdecResult.set(MESSAGE_BIN_SIZE - index - 1, gm.Dec(publicKey, secretKey, bobCipherText[index]));
    }
    
    // cout << "alice c : " << AdecResult << endl;
    // cout << "bob c : " << BdecResult << endl;

    if(decResult.none()){
        // cout << "gm : same" << endl;
        return true;
    }
    else
        return false;
    
}   


void GM_EqualityTest::printInitialTime(){
    cout << "Goldwasser-Micali Initial Time : " << initialTime.count() << "ms" << endl;
}
void GM_EqualityTest::printEncodingTime(){
    cout << "Goldwasser-Micali Encoding Time : " << encodingTime.count() << "ms" << endl;
}
void GM_EqualityTest::printStep1Time(){
    cout << "Goldwasser-Micali Step1 Time : " << step1Time.count() << "ms" << endl;
}
void GM_EqualityTest::printStep2Time(){
    cout << "Goldwasser-Micali Step2 Time : " << step2Time.count() << "ms" << endl;
}
void GM_EqualityTest::printStep3Time(){
    cout << "Goldwasser-Micali Step3 Time : " << step3Time.count() << "ms" << endl;
}
void GM_EqualityTest::printTotalTime(){
    cout << "Goldwasser-Micali Total Time : " << totalTime.count() << "ms" << endl;

}

