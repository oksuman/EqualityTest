// g++ -o ece_test ECE_Test.cpp ECE.cpp -lssl -lcrypto

#include <iostream>
#include <cstdlib>
#include <stdlib.h>
#include <ctime>
#include <chrono>
#include "ECE.h"

using namespace std;
using namespace chrono;

int main(int argc, char* argv[]){

        /*
                EC ElGamal based Equality Protocol Test
                message : 0 ~ 2047 (char *)
        */
    system_clock::time_point Pa_total_start_time = system_clock::now();
    srand((unsigned int)time(NULL));
    for(int k=0; k<1; k++){
        // int m_Alice = rand() % 2048;
        // int m_Bob = rand() % 2048;
        
        int m_Alice = 300;
        int m_Bob = 300;
        
        int remainder;
        int Alice_size, Bob_size;
        
        if(m_Alice < 16)
            Alice_size = 2;
        else if(m_Alice < 256)
            Alice_size = 3;
        else if(m_Alice < 4096)
            Alice_size = 4;
        else
            Alice_size = 0;

        if(m_Bob < 16)
            Bob_size = 2;
        else if(m_Bob < 256)
            Bob_size = 3;
        else if(m_Bob < 4096)
            Bob_size = 4;
        else
            Bob_size = 0;
       
        unsigned char hex_m_Alice[5] = {'\0','\0','\0','\0','\0'};
        unsigned char hex_m_Bob[5] = {'\0','\0','\0','\0','\0'};
       
        for(int i=0; i<Alice_size; i++){
            remainder = m_Alice % 16;
            m_Alice /= 16;
            char ch;
            if(remainder >= 10)
                ch = remainder + 55;
            else
                ch = remainder + 48;
            hex_m_Alice[Alice_size - i -1] = ch; 
        }
        
        for(int i=0; i<Bob_size; i++){
            remainder = m_Bob % 16;
            m_Bob /= 16;
            char ch;
            if(remainder >= 10)
                ch = remainder + 55;
            else
                ch = remainder + 48;
            hex_m_Bob[Bob_size - i -1] = ch; 
        }
        
  
        // Initial Step
        ECE *ece = new ECE;
        ece->KeyGen();
       
        // Step 1
        CIPHERTEXT *c_Alice = ece->Enc(hex_m_Alice);
        cout << "A : " << ece->Dec(*c_Alice) << endl;
        // Step 2
        CIPHERTEXT *c_Bob = ece->Enc(hex_m_Bob);
        cout << "B : " << ece->Dec(*c_Bob) << endl;
        unsigned char *s = ece->getRandomElement();
        CIPHERTEXT *c_sub = ece->Sub(*c_Bob, *c_Alice);
        CIPHERTEXT *c_res = ece->Scalar_Mul(s, *c_sub);

        // Step 3
        unsigned char *res = ece->Dec(*c_res);
        
        if(*(res+1) == 48)
            cout << "same" << endl;
    }
    system_clock::time_point Pa_total_end_time = system_clock::now();
    milliseconds milli_pa = duration_cast<milliseconds>(Pa_total_end_time - Pa_total_start_time);
    cout << milli_pa.count() << "ms" << endl;
}

