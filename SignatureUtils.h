/*
 * SignatureUtils.h
 * By Dalton Messmer
 */

#pragma once

#include <string>
#include <optional>

namespace sigutils {

struct CertInfo
{
	std::string CN, O, L, S, C;
};

bool IsSigned(const std::string& filename);

std::optional<CertInfo> GetIssuer(const std::string& filename);
std::optional<CertInfo> GetSubject(const std::string& filename);

bool GetIssuerName(const std::string& filename, std::string& issuer);
bool GetSubjectName(const std::string& filename, std::string& subject);

} // namespace sigutils
