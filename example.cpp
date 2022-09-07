/*
 * example.cpp
 * By Dalton Messmer
 */

#include "SignatureUtils.h"
#include <iostream>

int main()
{
    const std::string filename = R"(C:\Windows\system32\ws2_32.dll)";
    std::cout << "For '" << filename << "':\n";

    if (IsSigned(filename))
    {
        std::string issuer;
        if (GetDigitalSignatureIssuer(filename, issuer))
        {
            std::cout << "An error occurred.\n";
            return 1;
        }

        std::string subject;
        if (GetDigitalSignatureSubject(filename, subject))
        {
            std::cout << "An error occurred.\n";
            return 1;
        }
        std::cout << "Issuer:  '" << issuer << "'\n";
        std::cout << "Subject: '" << subject << "'\n";
    }
    else
    {
        std::cout << "Not digitally signed.\n";
    }

    return 0;
}
