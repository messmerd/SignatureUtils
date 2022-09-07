/*
 * example.cpp
 * By Dalton Messmer
 */

#include "SignatureUtils.h"
#include <iostream>

using namespace sigutils;

static void PrintCertInfo(const CertInfo& info);

int main(int argc, char* argv[])
{
	const std::string filename = argc == 2 ? argv[1] : R"(C:\Windows\system32\ws2_32.dll)";
	std::cout << "For '" << filename << "':\n\n";

	if (IsSigned(filename))
	{
		if (auto issuerName = GetIssuerName(filename); issuerName.has_value())
		{
			std::cout << "Issuer name:  '" << issuerName.value() << "'\n";
		}

		if (auto subjectName = GetSubjectName(filename); subjectName.has_value())
		{
			std::cout << "Subject name:  '" << subjectName.value() << "'\n";
		}

		std::cout << "\n";

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
		std::cout << "File is not digitally signed or does not exist.\n";
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
