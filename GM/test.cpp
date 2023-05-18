#include <iostream>
#include <bitset>

int main()
{
    std::string binary = std::bitset<40>(100).to_string(); //to binary
    std::cout<<binary<<"\n";

    unsigned long decimal = std::bitset<8>(binary).to_ulong();
    std::cout<<decimal<<"\n";
    return 0;
}