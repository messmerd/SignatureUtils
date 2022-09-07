/*
 * example.cpp
 * By Dalton Messmer
 */

#include "SignatureUtils.h"
#include <iostream>

using namespace sigutils;

static void PrintCertInfo(const CertInfo& info);

int main()
{
	const std::string filename = R"(C:\Windows\system32\ws2_32.dll)";
	std::cout << "For '" << filename << "':\n\n";

	if (IsSigned(filename))
	{
		std::string issuerName;
		if (GetIssuerName(filename, issuerName))
		{
			std::cout << "An error occurred.\n";
			return 1;
		}

		std::string subjectName;
		if (GetSubjectName(filename, subjectName))
		{
			std::cout << "An error occurred.\n";
			return 1;
		}
		std::cout << "Issuer name:  '" << issuerName << "'\n";
		std::cout << "Subject name: '" << subjectName << "'\n\n";

		if (auto issuer = GetIssuer(filename); issuer.has_value())
		{
			std::cout << "Issuer info:\n";
			PrintCertInfo(issuer.value());
		}
		if (auto subject = GetSubject(filename); subject.has_value())
		{
			std::cout << "Subject info:\n";
			PrintCertInfo(subject.value());
		}
	}
	else
	{
		std::cout << "Not digitally signed.\n";
	}

	return 0;
}

void PrintCertInfo(const CertInfo& info)
{
	std::cout << "\tCN: " << info.CN << "\n";
	std::cout << "\t O: " << info.O  << "\n";
	std::cout << "\t L: " << info.L  << "\n";
	std::cout << "\t S: " << info.S  << "\n";
	std::cout << "\t C: " << info.C  << "\n";
}
