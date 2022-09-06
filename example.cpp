/*
 * example.cpp
 * By Dalton Messmer
 */

#include "SignatureUtils.h"
#include <iostream>

int main()
{
    const std::string filename = R"(C:\Windows\system32\ws2_32.dll)";
    std::string subject;
    if (GetDigitalSignatureSubject(filename, subject))
    {
        std::cout << "An error occurred.\n";
        return 1;
    }
    std::cout << "Subject of '" << filename << "': '" << subject << "'\n";
    return 0;
}
